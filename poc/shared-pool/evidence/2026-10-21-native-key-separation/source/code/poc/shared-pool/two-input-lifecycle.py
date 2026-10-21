#!/usr/bin/env python3
"""Offline own-key admission/recovery experiment. Never connects or broadcasts.

All artifacts, including private backups and diagnostics, stay in a fresh 0700
directory. Publication is a separate, explicit allowlist operation. Synthetic
funding-parent ancestry is intentional and is not accepted-chain evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
PIN = {
    "sha256": "6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593",
    "bytes": 962197520,
}
VK_SHA256 = "9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef"
GUARD = r"""
import json, os, sys
interfaces = [line.split(':')[0].strip() for line in open('/proc/net/dev') if ':' in line]
assert not os.path.exists('/home/luke'), 'host home visible'
assert interfaces == ['lo'], 'external network visible'
assert not os.path.exists('/controller'), 'controller visible'
print(json.dumps({'isolation': {
    'host_home_visible': False, 'network_interfaces': interfaces,
    'controller_directory_visible': False,
    'scope': 'fresh process and user/mount/PID/network namespaces; same physical host'
}}), flush=True)
os.execv('/program', ['/program'] + sys.argv[1:])
"""


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    with path.open("x") as f:
        os.chmod(path, 0o600)
        json.dump(value, f, indent=2)
        f.write("\n")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def sandbox(binary, out, mounts, arguments):
    command = [
        "bwrap", "--unshare-all", "--die-with-parent", "--new-session",
        "--clearenv", "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64", "--proc", "/proc",
        "--dev", "/dev", "--tmpfs", "/tmp", "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "RAYON_NUM_THREADS", "4",
        "--ro-bind", str(binary), "/program", "--bind", str(out), "/out",
    ]
    for mount in mounts:
        source, destination, *mode = mount
        command += ["--bind" if mode == ["rw"] else "--ro-bind", str(source), destination]
    return command + [
        "--", "/usr/bin/time", "-v", "-o", "/out/resources.txt",
        "/usr/bin/python3", "-c", GUARD, *arguments,
    ]


class Experiment:
    def __init__(self, root, params, wallet_binary, helper_binary):
        self.root, self.params = root, params
        self.wallet_binary, self.helper_binary = wallet_binary, helper_binary
        self.public = root / "public"
        self.public.mkdir(mode=0o700)
        self.logs = root / "processes"
        self.logs.mkdir(mode=0o700)
        self.pin = root / "pin.json"
        save(self.pin, PIN)
        self.operations, self.controls, self.audits = [], [], []
        self.workers = []
        self.counter = 0

    def logdir(self, name):
        self.counter += 1
        out = self.logs / f"{self.counter:02d}-{name}"
        out.mkdir(mode=0o700)
        return out

    def run(self, name, binary, mounts, args, expect_ok=True):
        out = self.logdir(name)
        begin = time.monotonic()
        result = subprocess.run(
            sandbox(binary, out, mounts, args), text=True, capture_output=True,
            check=False,
        )
        (out / "stdout.txt").write_text(result.stdout)
        (out / "stderr.txt").write_text(result.stderr)
        lines = result.stdout.splitlines()
        if not lines:
            raise RuntimeError(f"{name}: no isolation audit; see {out}")
        audit = json.loads(lines[0])
        assert "isolation" in audit, (name, "missing isolation guard")
        self.audits.append({"process": name, **audit["isolation"]})
        if expect_ok != (result.returncode == 0):
            raise RuntimeError(f"{name}: unexpected status {result.returncode}; see {out}")
        if not expect_ok:
            self.controls.append({"name": name, "rejected": True})
            return None
        if len(lines) != 2:
            raise RuntimeError(f"{name}: expected one JSON response; see {out}")
        value = json.loads(lines[1])
        save(out / "result.json", value)
        save(out / "timing.json", {"wall_seconds": time.monotonic() - begin})
        return value

    def mounts(self, backup=None):
        mounts = [
            (self.public, "/public"), (self.pin, "/pin.json"),
            (self.params / "vk.bin", "/vk.bin"),
        ]
        if backup is not None:
            mounts.append((backup, "/backup.json"))
        return mounts

    def snapshot(self, name, previous=None, transaction=None, parent=None):
        target = self.public / name
        target.mkdir(mode=0o700)
        source = previous or self.root / "founder" / "public"
        for filename in ["descriptor.json", "vk.bin"]:
            shutil.copyfile(source / filename, target / filename)
        lineage = load(source / "lineage.json")
        parents = load(source / "parents.json")
        if transaction is not None:
            lineage.append(transaction)
        if parent is not None:
            parents.append(parent)
        save(target / "lineage.json", lineage)
        save(target / "parents.json", parents)
        checked = self.run(
            f"checkpoint-{name}", self.helper_binary,
            [(target, "/snapshot")], ["checkpoint", "/snapshot"],
        )
        save(target / "head.json", checked["head"])
        save(target / "checked.json", checked)
        return target

    def create(self, name, snapshot):
        out = self.root / name
        out.mkdir(mode=0o700)
        self.run(
            f"initialize-{name}", self.wallet_binary,
            [(snapshot, "/public"), (self.pin, "/pin.json"),
             (out, "/destination", "rw")],
            ["create", "/public/descriptor.json", "/public/vk.bin",
             "/pin.json", "/destination/wallet"],
        )
        return out / "wallet" / "backup.json", load(out / "wallet" / "receive.json")

    def inspect(self, name, backup, snapshot, expect_ok=True):
        return self.run(
            name, self.wallet_binary, self.mounts(backup),
            ["inspect", "/backup.json", f"/public/{snapshot.name}/descriptor.json",
             f"/public/{snapshot.name}/vk.bin", f"/public/{snapshot.name}/lineage.json",
             f"/public/{snapshot.name}/parents.json", f"/public/{snapshot.name}/head.json"],
            expect_ok,
        )

    def worker(self, name, backup):
        worker = Worker(self, name, backup)
        self.workers.append(worker)
        return worker

    def finish(self):
        for worker in self.workers:
            worker.stop()


class Worker:
    def __init__(self, experiment, name, backup):
        self.experiment, self.name = experiment, name
        self.out = experiment.logdir(name)
        self.stderr = (self.out / "stderr.txt").open("x")
        self.begin = time.monotonic()
        mounts = experiment.mounts(backup) + [(experiment.params / "pk.bin", "/pk.bin")]
        self.process = subprocess.Popen(
            sandbox(experiment.wallet_binary, self.out, mounts,
                    ["serve", "/pk.bin", "/pin.json", "/vk.bin"]),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
            text=True, bufsize=1,
        )
        audit = json.loads(self.process.stdout.readline())
        assert "isolation" in audit
        experiment.audits.append({"process": name, **audit["isolation"]})
        self.responses = []
        self.stopped = False

    def request(self, snapshot, action, expect_ok=True):
        base = f"/public/{snapshot.name}"
        request = {
            "backup": "/backup.json", "descriptor": base + "/descriptor.json",
            "vk": base + "/vk.bin", "lineage": base + "/lineage.json",
            "parents": base + "/parents.json", "head": base + "/head.json",
            "action": action,
        }
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(f"{self.name}: worker terminated; see {self.out}")
        response = json.loads(line)
        self.responses.append(response)
        if response.get("ok") != expect_ok:
            raise RuntimeError(f"{self.name}: unexpected response {response.get('error', 'success')}")
        if not expect_ok:
            self.experiment.controls.append({
                "name": f"{self.name}-{action['action']}-invalid-request",
                "rejected": True, "error": response.get("error"),
            })
            return None
        result = response["result"]
        assert set(result) == {
            "scope", "chain_acceptance_verified", "descriptor_sha256", "base_head",
            "transaction", "bundle", "metrics", "preparation_ms", "proof_ms",
            "native_validation_ms", "constraints",
        }, "prepared transaction exported unexpected metadata"
        assert result["chain_acceptance_verified"] is False
        return result

    def stop(self):
        if self.stopped:
            return
        self.stopped = True
        self.process.stdin.close()
        # No operational timeout aborts a valid proof/experiment.
        status = self.process.wait()
        self.stderr.close()
        save(self.out / "responses.json", self.responses)
        save(self.out / "timing.json", {
            "wall_seconds": time.monotonic() - self.begin, "exit_code": status,
        })
        if status:
            raise RuntimeError(f"{self.name}: worker exit {status}; see {self.out}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--params", type=Path, required=True)
    parser.add_argument("--wallet-binary", type=Path, required=True)
    parser.add_argument("--helper-binary", type=Path, required=True)
    parser.add_argument("--output-parent", type=Path,
                        default=Path("/home/luke/kpi-private/admission-recovery-m2"))
    args = parser.parse_args()
    os.umask(0o077)
    args.output_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = args.output_parent / str(uuid.uuid4())
    root.mkdir(mode=0o700)
    print(f"Private experiment directory: {root}", flush=True)
    assert (args.params / "pk.bin").stat().st_size == PIN["bytes"]
    assert digest(args.params / "vk.bin") == VK_SHA256
    experiment = Experiment(root, args.params.resolve(),
                            args.wallet_binary.resolve(), args.helper_binary.resolve())
    try:
        # The helper generates only A. B and C do not exist at this point.
        experiment.run(
            "founder", experiment.helper_binary,
            [(args.params / "vk.bin", "/vk.bin"), (experiment.pin, "/pin.json"),
             (root, "/destination", "rw")],
            ["founder", "/vk.bin", "/pin.json", "/destination/founder"],
        )
        initial = experiment.snapshot("00-founded")
        a_backup = root / "founder" / "backup.json"
        a_receive = load(root / "founder" / "receive.json")
        a = experiment.worker("A-original", a_backup)
        bootstrap = a.request(initial, {
            "action": "pay", "positions": [0], "recipient": a_receive,
            "amount_sompi": "1960000000",
        })
        bootstrapped = experiment.snapshot("01-bootstrapped", initial, bootstrap["transaction"])
        print("Founder bootstrap validated; now independently creating B and C.", flush=True)
        b_backup, b_receive = experiment.create("B", bootstrapped)
        c_backup, c_receive = experiment.create("C", bootstrapped)
        b_backup_hash = digest(b_backup)
        b_funding = experiment.run(
            "B-public-funding", experiment.wallet_binary,
            experiment.mounts(b_backup),
            ["funding", "/backup.json", "/public/01-bootstrapped/descriptor.json", "0"],
        )
        parent = experiment.run(
            "B-synthetic-funding-parent", experiment.helper_binary, [],
            ["fund", b_funding["script_public_key"]],
        )
        save(root / "B-synthetic-parent.json", parent)
        joining = experiment.snapshot("02-B-parent", bootstrapped, parent=parent["transaction"])
        b = experiment.worker("B-original-admission", b_backup)
        admission = b.request(joining, {
            "action": "admit", "txid": parent["transaction"]["id"],
            "index": 0, "native_key_index": 0,
        })
        admitted = experiment.snapshot("03-B-admitted", joining, admission["transaction"])
        b.stop()
        payment = a.request(admitted, {
            "action": "pay", "positions": [1], "recipient": b_receive,
            "amount_sompi": "1920000000",
        })
        received = experiment.snapshot("04-B-offline-receipt", admitted, payment["transaction"])
        a.stop()
        assert digest(b_backup) == b_backup_hash
        print("B admitted and received while offline; original wallet workers stopped.", flush=True)
        first_scan = experiment.inspect("B-first-clean-recovery-scan", b_backup, received)
        assert first_scan["balance_sompi"] == "3080000000"
        assert {n["position"] for n in first_scan["notes"] if not n["spent"]} == {3, 5}
        save(root / "first-recovery-scan.json", first_scan)
        # Recovery has one original backup and public history. C's worker has
        # only C's backup. At most two proving keys are loaded concurrently.
        restored = experiment.worker("B-first-clean-recovery", b_backup)
        c = experiment.worker("C-independent-exit", c_backup)
        for action in [
            {"action": "pay", "positions": [1], "recipient": c_receive, "amount_sompi": "1000000000"},
            {"action": "pay", "positions": [3, 3], "recipient": c_receive, "amount_sompi": "1000000000"},
            {"action": "pay", "positions": [3, 5], "recipient": c_receive, "amount_sompi": "1"},
        ]:
            restored.request(received, action, False)
        b_payment = restored.request(received, {
            "action": "pay", "positions": [3, 5], "recipient": c_receive,
            "amount_sompi": "1000000000",
        })
        changed = experiment.snapshot("05-B-payment-change", received, b_payment["transaction"])
        restored.stop()
        c_exit = c.request(changed, {
            "action": "exit", "positions": [7], "native_key_index": 7,
        })
        c_exited = experiment.snapshot("06-C-exited", changed, c_exit["transaction"])
        c.stop()
        assert digest(b_backup) == b_backup_hash
        second_scan = experiment.inspect("B-second-clean-recovery-scan", b_backup, c_exited)
        assert second_scan["balance_sompi"] == "2040000000"
        assert {n["position"] for n in second_scan["notes"] if not n["spent"]} == {8}
        assert {n["position"] for n in second_scan["notes"] if n["spent"]} == {3, 5}
        save(root / "second-recovery-scan.json", second_scan)
        b_again = experiment.worker("B-second-clean-recovery", b_backup)
        b_again.request(c_exited, {
            "action": "exit", "positions": [3, 5], "native_key_index": 3,
        }, False)
        final_exit = b_again.request(c_exited, {
            "action": "exit", "positions": [8], "native_key_index": 8,
        })
        final = experiment.snapshot("07-drained", c_exited, final_exit["transaction"])
        b_again.stop()
        final_checked = load(final / "checked.json")["replay"]
        assert final_checked["drained"] is True
        assert final_checked["accounting"]["initial_reserve_sompi"] == "2000000000"
        assert final_checked["accounting"]["admitted_sompi"] == "1200000000"
        assert final_checked["accounting"]["paid_sompi"] == "2960000000"
        assert final_checked["accounting"]["pool_fees_sompi"] == "240000000"
        assert final_checked["accounting"]["remaining_reserve_sompi"] == "0"
        assert digest(b_backup) == b_backup_hash
        assert digest(initial / "descriptor.json") == digest(final / "descriptor.json")
        save(final / "B-terminal-payout.json", final_exit["transaction"])
        payout = experiment.run(
            "B-restored-native-payout-spend", experiment.helper_binary,
            [(b_backup, "/backup.json"), (final, "/public")],
            ["payout-spend", "/backup.json", "/public/descriptor.json",
             "/public/B-terminal-payout.json", "8"],
        )
        save(root / "payout-spend.json", payout)
        # A separate fork from the admitted state: a genuine proof commits to a
        # ciphertext B can open, but that opening disagrees with the output
        # commitment. This is different from damaging an old proof's bytes.
        recipient_path = root / "B-public-receive.json"
        save(recipient_path, b_receive)
        bad = experiment.run(
            "A-genuine-malformed-delivery", experiment.helper_binary,
            [(a_backup, "/backup.json"), (admitted, "/public"),
             (recipient_path, "/recipient.json"),
             (args.params / "pk.bin", "/pk.bin"), (experiment.pin, "/pin.json")],
            ["bad-delivery", "/backup.json", "/public", "/recipient.json",
             "/pk.bin", "/pin.json"],
        )
        fork = experiment.snapshot("fork-malformed-delivery", admitted, bad["transaction"])
        fork_scan = experiment.inspect("B-malformed-delivery-scan", b_backup, fork)
        assert fork_scan["balance_sompi"] == "1160000000"
        assert {n["position"] for n in fork_scan["notes"] if not n["spent"]} == {3}
        existing_claim = root / "B-fork-existing-claim.json"
        save(existing_claim, {"action": "exit", "positions": [3], "native_key_index": 3})
        experiment.run(
            "B-valid-claim-after-malformed-delivery", experiment.helper_binary,
            [(b_backup, "/backup.json"), (fork, "/public"),
             (existing_claim, "/action.json")],
            ["prepare-check", "/backup.json", "/public", "/action.json"],
        )
        experiment.controls.append({
            "name": "genuine-proof-malformed-delivery-does-not-credit-or-block-prior-claim",
            "passed": True,
        })
        # Missing/changed data must fail against the separately supplied head.
        for name in ["wrong-head", "missing-history", "missing-funding-parent", "wrong-pool"]:
            control = experiment.public / ("control-" + name)
            shutil.copytree(received, control)
            if name == "wrong-head":
                value = load(control / "head.json")
                value["last_full_hash"] = "00" * 32
                (control / "head.json").write_text(json.dumps(value))
            elif name == "missing-history":
                value = load(control / "lineage.json")[:-1]
                (control / "lineage.json").write_text(json.dumps(value))
            elif name == "missing-funding-parent":
                value = load(control / "parents.json")[:-1]
                (control / "parents.json").write_text(json.dumps(value))
            else:
                value = load(control / "descriptor.json")
                value["domain"][0] ^= 1
                (control / "descriptor.json").write_text(json.dumps(value))
            experiment.inspect(name, b_backup, control, expect_ok=False)
        report = {
            "scope": "offline genuine v6 proofs and native validation; synthetic ancestry",
            "chain_acceptance_verified": False,
            "pool_proofs": 6, "native_pool_transactions": 7,
            "separate_malformed_delivery_fork_proofs": 1,
            "malformed_delivery_neither_credited_nor_blocked_valid_prior_claim": True,
            "initial_descriptor_unchanged": digest(initial / "descriptor.json") == digest(final / "descriptor.json"),
            "B_backup_created_after_bootstrap_before_admission": True,
            "B_original_backup_unchanged": True,
            "B_backup_sha256": b_backup_hash,
            "original_workers_stopped_before_recovery": True,
            "original_A_backup_inaccessible_during_B_recovery": True,
            "terminal_payout_spend_native_validated": payout["native_validation_passed"],
            "parameters": PIN, "vk_sha256": VK_SHA256,
            "accounting": final_checked["accounting"],
            "controls": experiment.controls, "process_isolation": experiment.audits,
            "limits": [
                "No accepted-chain proof, transaction broadcast, or actual funding.",
                "Expected heads are this experiment driver's offline oracle, not independently authenticated chain endpoints.",
                "Same-host process/mount/network isolation is not independent-host recovery.",
                "No security audit or real-world privacy/performance qualification.",
                "Malformed delivery control uses a separate fork; its fee is not included in the six-operation accounting.",
                "Existing-claim control after malformed delivery checked request/circuit preparation; no eighth proof was generated.",
            ],
        }
        save(root / "report.json", report)
        print(json.dumps({"passed": True, "private_directory": str(root),
                          "pool_proofs": 6, "malformed_delivery_fork_proofs": 1,
                          "reserve_sompi": "0"}), flush=True)
    finally:
        experiment.finish()


if __name__ == "__main__":
    main()

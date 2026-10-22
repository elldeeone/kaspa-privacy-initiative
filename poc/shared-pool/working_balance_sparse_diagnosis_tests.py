"""Public orchestration controls; never read an old attempt or private truth."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import working_balance_sparse_diagnosis as runner
import working_balance_trial as original_trial
from working_balance_observer_tests import Fixture


class RunnerControls(unittest.TestCase):
    def test_json_rejects_duplicate_fields_and_nonfinite_values(self):
        for data in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                runner.parse(data)

    def test_save_and_copy_are_create_only_and_pin_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root/"source", root/"target"
            source.write_bytes(b"public bytes")
            with self.assertRaisesRegex(ValueError, "artifact drift"):
                runner.copy_pinned(source,target,"0"*64)
            self.assertFalse(target.exists())
            runner.copy_pinned(source,target,runner.sha(source))
            with self.assertRaises(FileExistsError):
                runner.copy_pinned(source,target,runner.sha(source))
            runner.save(root/"result.json",dict(public=True))
            with self.assertRaises(FileExistsError):
                runner.save(root/"result.json",dict(public=False))

    def test_symlinks_and_parent_traversal_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"source").write_text("public")
            (root/"alias").symlink_to(root/"source")
            with self.assertRaisesRegex(ValueError,"unsafe artifact path"):
                runner.plain(root/"alias")
            with self.assertRaisesRegex(ValueError,"unsafe artifact path"):
                runner.plain(root/".."/root.name/"source")

    def trace_fixture(self):
        guess = dict(sender=8,recipient=9,amount=1000000000,relationship_rank=[0,0,0,0])
        public = dict(events=[dict(event=0,mode=0,payout=0),dict(event=1,mode=1,payout=0),
                              dict(event=2,mode=1,payout=100)])
        guesses = {name:copy.deepcopy(guess) for name in runner.BASE}
        row = dict(event=1,event_id="public-event",all_guesses=guesses,guess=copy.deepcopy(guess),full_book_verified=True)
        old = dict(rows=[dict(event=1,event_id="public-event",guesses=copy.deepcopy(guesses))])
        return public,[row],old

    def test_trace_equality_covers_all_thirteen_guesses_and_ranks(self):
        public,rows,old = self.trace_fixture()
        runner.verify_trace(rows,old,public)
        for variant in runner.BASE:
            changed=copy.deepcopy(rows)
            changed[0]["all_guesses"][variant]["relationship_rank"][0]=1
            with self.assertRaisesRegex(ValueError,"frozen guesses or ranks"):
                runner.verify_trace(changed,old,public)

    def test_trace_requires_all_public_targets_and_full_book(self):
        public,rows,old=self.trace_fixture()
        with self.assertRaisesRegex(ValueError,"all public trace targets"):
            runner.verify_trace([],old,public)
        with self.assertRaisesRegex(ValueError,"original final target roster"):
            runner.verify_trace(rows,dict(rows=[]),public)
        rows[0]["full_book_verified"]=False
        with self.assertRaisesRegex(ValueError,"frozen guesses or ranks"):
            runner.verify_trace(rows,old,public)

    def test_truth_staging_cannot_begin_without_public_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(runner,"verify_public_barrier",side_effect=ValueError("missing public seal")), \
                 patch.object(runner,"verify_old_public") as old, patch.object(runner,"copy_pinned") as copyfile:
                with self.assertRaisesRegex(ValueError,"missing public seal"):
                    runner.stage_classification(root)
            old.assert_not_called(); copyfile.assert_not_called()
            self.assertFalse((root/"classification-inputs").exists())

    def test_public_barrier_rejects_missing_trace_before_classification(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"freeze.json").write_text("{}")
            runner.save(root/"public-seal.json",dict(complete=True,freeze_sha256=runner.sha(root/"freeze.json"),
                        truth_opened=False,seed_opened=False,records=[]))
            with patch.object(runner,"check",return_value={}):
                with self.assertRaisesRegex(ValueError,"four public trace seal barrier"):
                    runner.verify_public_barrier(root)

    def test_public_barrier_binds_process_and_isolation_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/"runs").mkdir(); (root/"freeze.json").write_text("{}")
            records=[]
            for index,(arm,profile) in enumerate((a,p) for a in runner.ARMS for p in runner.PROFILES):
                folder=root/"runs"/f"trace-{index}"; folder.mkdir()
                runner.save(folder/"result.json",dict(rows=[]))
                runner.save(folder/"process.json",dict(returncode=0))
                runner.save(folder/"isolation.json",dict(no_home=True,no_proc=True,interfaces=["lo"],
                    nested_userns_denied=True,mode="trace",mounts=["/public.json","/directory.json","/view.json"],
                    truth_mounted=False,seed_mounted=False))
                runner.save(folder/"inputs.json",{})
                records.append(dict(arm=arm,profile=profile,files={n:runner.sha(folder/n) for n in
                    ("result.json","process.json","isolation.json","inputs.json")}))
            runner.save(root/"public-seal.json",dict(complete=True,freeze_sha256=runner.sha(root/"freeze.json"),
                        truth_opened=False,seed_opened=False,records=records))
            with patch.object(runner,"check",return_value={}):
                runner.verify_public_barrier(root)
                (root/"runs"/"trace-2"/"result.json").write_text('{"rows":[1]}')
                with self.assertRaisesRegex(ValueError,"public trace seal drift"):
                    runner.verify_public_barrier(root)

    def test_sandbox_rejects_truth_or_attempt_mount_in_public_mode(self):
        class Original:
            @staticmethod
            def sandbox():
                return ["bwrap"]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/"runs").mkdir()
            with patch.object(runner,"old_module",return_value=Original()):
                with self.assertRaisesRegex(ValueError,"sandbox input allowlist"):
                    runner.sandbox_stage(root,"trace-bad","trace",[(root,"/data")],[],"")

    def test_source_roster_includes_controls_and_no_generator_in_new_sandbox(self):
        self.assertEqual(len(runner.OLD_SOURCES),9)
        for name in ("working_balance_sparse_trace_tests.py","working_balance_sparse_classify_tests.py",
                     "working_balance_sparse_diagnosis_tests.py",runner.SPEC):
            self.assertIn(name,runner.SOURCES)
        self.assertNotIn("working_balance_model.py",runner.SOURCES)
        self.assertNotIn("seed.json",runner.OLD_METADATA)

    def test_actual_public_bwrap_trace_writes_parseable_json(self):
        fixture=Fixture()
        fixture.add(1)
        fixture.add(1,payout=20*100000000)
        fixture.add(2,payout=19*100000000+20000000)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/"runs").mkdir()
            for name,value in (("public",fixture.public),("directory",fixture.directory),("view",fixture.view)):
                runner.save(root/(name+".json"),value)
            with patch.object(runner,"old_module",return_value=original_trial):
                folder,result=runner.sandbox_stage(root,"public-fixture","trace",
                    [(root/(name+".json"),"/"+name+".json") for name in ("public","directory","view")],
                    [runner.HERE/"working_balance_observer.py",runner.HERE/"working_balance_sparse_trace.py"],
                    runner.trace_script())
            self.assertEqual(set(result),{"rows"})
            original=fixture.observe()
            runner.verify_trace(result["rows"],original,fixture.public)
            self.assertEqual(json.loads((folder/"result.json").read_text()),result)
            self.assertEqual((folder/"result.json").read_bytes()[-1:],b"\n")
            isolation=runner.load(folder/"isolation.json")
            self.assertFalse(isolation["truth_mounted"])
            self.assertFalse(isolation["seed_mounted"])
            self.assertTrue(isolation["no_home"] and isolation["no_proc"])

    def test_classification_stage_rejects_extra_seed_and_changed_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory)
            names=set(runner.public_names()) | {a+"-truth.json" for a in runner.ARMS} | {
                a+"-"+p+"-trace.json" for a in runner.ARMS for p in ("C","pooled")}
            for name in names:
                runner.save(stage/name,{"public_control":True})
            runner.save(stage/"manifest.json",dict(files={n:runner.sha(stage/n) for n in names},
                        public_seal_sha256="0"*64,seed_included=False))
            runner.verify_stage(stage)
            (stage/"seed.json").write_text('{"not_a_real_seed":true}')
            with self.assertRaisesRegex(ValueError,"closed classification stage"):
                runner.verify_stage(stage)
            (stage/"seed.json").unlink()
            (stage/"whole-truth.json").write_text('{"public_control":false}')
            with self.assertRaisesRegex(ValueError,"classification stage drift"):
                runner.verify_stage(stage)

    def test_both_subprocess_wrappers_compile(self):
        compile(runner.trace_script(),"public-trace-wrapper","exec")
        compile(runner.classify_script(),"private-classification-wrapper","exec")


if __name__ == "__main__":
    unittest.main()

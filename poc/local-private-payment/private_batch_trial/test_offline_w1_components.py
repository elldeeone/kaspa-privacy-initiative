import copy
from pathlib import Path
import tempfile
import unittest
import uuid

import offline_w1_components as components
import offline_w1_fixture as fixture


def plan():
    return {
        "run_id": str(uuid.uuid4()),
        "source_instance_epoch_id": str(uuid.uuid4()),
        "plan_identity_sha256": uuid.uuid4().hex * 2,
        "source_closure_sha256": uuid.uuid4().hex * 2,
    }


class OfflineW1ComponentBuilderControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plan = plan()

    def tearDown(self):
        self.temporary.cleanup()

    def test_completed_bundle_is_reused_without_regeneration(self):
        calls = []

        def produce(directory):
            calls.append(directory)
            fixture.write_new(directory / "leaf.bin", b"genuine-proof")

        first = components.cached_bundle(
            self.root, self.plan, "round-1-components", "owner-0",
            ("leaf.bin",), produce)
        second = components.cached_bundle(
            self.root, self.plan, "round-1-components", "owner-0",
            ("leaf.bin",), lambda _: self.fail("cache regenerated"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(first["leaf.bin"].read_bytes(), b"genuine-proof")
        self.assertEqual(first, second)

    def test_interrupted_bundle_is_not_admitted_and_resume_succeeds(self):
        def interrupted(directory):
            fixture.write_new(directory / "leaf.bin", b"partial")
            raise RuntimeError("simulated interruption")

        with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
            components.cached_bundle(
                self.root, self.plan, "round-1-components", "owner-1",
                ("leaf.bin",), interrupted)
        stage = self.root / components.WORK_DIRECTORY / "round-1-components"
        self.assertFalse((stage / "owner-1").exists())
        self.assertTrue(any(path.name.startswith(".owner-1.tmp-")
                            for path in stage.iterdir()))
        resumed = components.cached_bundle(
            self.root, self.plan, "round-1-components", "owner-1",
            ("leaf.bin",),
            lambda directory: fixture.write_new(
                directory / "leaf.bin", b"complete"))
        self.assertEqual(resumed["leaf.bin"].read_bytes(), b"complete")

    def test_cache_substitution_and_cross_run_replay_refuse(self):
        selected = components.cached_bundle(
            self.root, self.plan, "round-2-components", "owner-2",
            ("leaf.bin",),
            lambda directory: fixture.write_new(
                directory / "leaf.bin", b"selected"))
        leaf = selected["leaf.bin"]
        leaf.chmod(0o600)
        leaf.write_bytes(b"mutated!")
        leaf.chmod(0o400)
        with self.assertRaisesRegex(
                fixture.Refused, "component-cache-receipt-binding"):
            components.load_cached_bundle(
                self.root, self.plan, "round-2-components", "owner-2",
                ("leaf.bin",))

        other_root = self.root / "other"
        other_root.mkdir()
        components.cached_bundle(
            other_root, self.plan, "bootstrap", "owner-0",
            ("leaf.bin",),
            lambda directory: fixture.write_new(
                directory / "leaf.bin", b"selected"))
        replay = copy.deepcopy(self.plan)
        replay["run_id"] = str(uuid.uuid4())
        with self.assertRaisesRegex(
                fixture.Refused, "component-cache-receipt-binding"):
            components.load_cached_bundle(
                other_root, replay, "bootstrap", "owner-0",
                ("leaf.bin",))

    def test_checkpoint_prefix_refuses_gap_and_aggregate_scope(self):
        fixture.stage_path(self.root, "bootstrap").mkdir()
        self.assertEqual(components.completed_component_prefix(self.root),
                         ["bootstrap"])
        fixture.stage_path(self.root, "round-1-components").mkdir()
        with self.assertRaisesRegex(
                fixture.Refused, "component-builder-checkpoint-gap-or-scope"):
            components.completed_component_prefix(self.root)

        other = self.root / "other-prefix"
        other.mkdir()
        for stage in components.COMPONENT_STAGES:
            fixture.stage_path(other, stage).mkdir()
        fixture.stage_path(other, "round-1-aggregate").mkdir()
        with self.assertRaisesRegex(
                fixture.Refused, "component-builder-checkpoint-gap-or-scope"):
            components.completed_component_prefix(other)


if __name__ == "__main__":
    unittest.main()

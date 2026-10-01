import importlib.util
from pathlib import Path
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("run_baseline", Path(__file__).with_name("run_baseline.py"))
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class BaselineHelpersTest(unittest.TestCase):
    def test_memory_units(self):
        self.assertEqual(baseline.memory_bytes("32MiB / 8GiB"), 32 * 1024 * 1024)
        self.assertEqual(baseline.memory_bytes("1.5GB / 8GB"), 1_500_000_000)
        with self.assertRaises(ValueError):
            baseline.memory_bytes("unknown")

    def test_wait_for_queued_instance_registration(self):
        api = mock.Mock()
        api.request.side_effect = [baseline.APIError(404, "pending"), {"status": "finished"}]
        with mock.patch.object(baseline.time, "sleep"), mock.patch.object(baseline, "peak_memory", return_value=42):
            state, peak, _ = baseline.wait_for_scan(api, "id", ("scanner",), 10)
        self.assertEqual(state["status"], "finished")
        self.assertEqual(peak, 42)


if __name__ == "__main__":
    unittest.main()

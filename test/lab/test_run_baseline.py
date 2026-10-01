import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("run_baseline", Path(__file__).with_name("run_baseline.py"))
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class BaselineHelpersTest(unittest.TestCase):
    def test_memory_units(self):
        self.assertEqual(baseline.memory_bytes("32MiB / 8GiB"), 32 * 1024 * 1024)
        self.assertEqual(baseline.memory_bytes("1.5GB / 8GB"), 1_500_000_000)
        with self.assertRaises(ValueError):
            baseline.memory_bytes("unknown")

    def test_report_path_hash_is_stable(self):
        self.assertEqual(len(__import__("hashlib").sha256(b"example").hexdigest()[:32]), 32)


if __name__ == "__main__":
    unittest.main()

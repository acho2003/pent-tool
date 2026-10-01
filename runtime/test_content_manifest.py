import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("content_manifest", Path(__file__).with_name("write-content-manifest.py"))
content_manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(content_manifest)


class ContentManifestTest(unittest.TestCase):
    def test_required_and_optional_are_distinct(self):
        lock = {"required": {"nuclei": "v1"}, "optional": {"katana": "v2"}}
        got = content_manifest.manifest(lock, lambda name: ["version"] if name == "nuclei" else None, "a=1\n")
        self.assertTrue(got["tools"]["nuclei"]["available"])
        self.assertFalse(got["tools"]["katana"]["available"])
        self.assertEqual(got["dpkg_package_count"], 1)

    def test_missing_required_fails(self):
        with self.assertRaisesRegex(RuntimeError, "nuclei"):
            content_manifest.manifest({"required": {"nuclei": "v1"}, "optional": {}}, lambda _: None, "")


if __name__ == "__main__":
    unittest.main()

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess
import os


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

    def test_broken_executable_is_not_available(self):
        result = subprocess.CompletedProcess(['scanner', '--version'], 127, '', 'missing library')
        with patch.object(content_manifest.shutil, 'which', return_value='/scanner'), patch.object(content_manifest.subprocess, 'run', return_value=result):
            self.assertIsNone(content_manifest.installed_version('scanner'))

    def test_scanner_specific_version_command(self):
        result = subprocess.CompletedProcess(['nikto', '-Version'], 0, 'Nikto 2.6.0', '')
        with patch.object(content_manifest.shutil, 'which', return_value='/usr/bin/nikto'), patch.object(content_manifest.subprocess, 'run', return_value=result) as execute:
            self.assertEqual(content_manifest.installed_version('nikto', ['-Version']), ['Nikto 2.6.0'])
            self.assertEqual(execute.call_args.args[0], ('/usr/bin/nikto', '-Version'))

    def test_documented_information_exit_is_accepted(self):
        result = subprocess.CompletedProcess(['masscan', '--version'], 1, 'Masscan version 1.3.2', '')
        with patch.object(content_manifest.shutil, 'which', return_value='/usr/bin/masscan'), patch.object(content_manifest.subprocess, 'run', return_value=result):
            self.assertEqual(content_manifest.installed_version('masscan', ['--version'], [0, 1]), ['Masscan version 1.3.2'])

    def test_metadata_probe_keeps_executable_requirement(self):
        command = ['python3', '-c', 'print("installed version")']
        result = subprocess.CompletedProcess(command, 0, 'installed version', '')
        with patch.object(content_manifest.shutil, 'which', return_value='/scanner'), patch.object(content_manifest.subprocess, 'run', return_value=result) as execute:
            self.assertEqual(content_manifest.installed_version('scanner', command=command), ['installed version'])
            self.assertEqual(execute.call_args.args[0], command)
        with patch.object(content_manifest.shutil, 'which', return_value=None), patch.object(content_manifest.subprocess, 'run') as execute:
            self.assertIsNone(content_manifest.installed_version('scanner', command=command))
            execute.assert_not_called()

    def test_version_probe_environment_is_scoped(self):
        result = subprocess.CompletedProcess(['testssl.sh', '--version'], 0, 'testssl.sh 3.3dev', '')
        with patch.object(content_manifest.shutil, 'which', return_value='/testssl.sh'), patch.object(content_manifest.subprocess, 'run', return_value=result) as execute:
            content_manifest.installed_version('testssl.sh', env_overrides={'NXDNS': '127.0.0.1:0'})
            self.assertEqual(execute.call_args.kwargs['env']['NXDNS'], '127.0.0.1:0')
            self.assertIsNot(execute.call_args.kwargs['env'], os.environ)


if __name__ == "__main__":
    unittest.main()

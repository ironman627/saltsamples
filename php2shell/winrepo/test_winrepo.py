"""Offline contract checks for the two ZIP-backed lab package definitions."""
from pathlib import Path
import unittest

import jinja2
import yaml

ROOT = Path(__file__).resolve().parent


class WinrepoTests(unittest.TestCase):
    def definition(self, name, arch='AMD64'):
        return yaml.safe_load(jinja2.Environment(undefined=jinja2.StrictUndefined)
                              .from_string((ROOT / (name + '.sls')).read_text())
                              .render(grains={'cpuarch': arch}))

    def test_registry_identity_matches_installer(self):
        script = (ROOT / 'php2shell_install/install.ps1').read_text()
        for name in ('php83', 'apache24'):
            data = self.definition(name)
            self.assertEqual(list(data), [name])
            self.assertEqual(len(data[name]), 1)
            version, entry = next(iter(data[name].items()))
            self.assertIn(entry['full_name'], script)
            self.assertIn('-Version ' + version + ' ', entry['install_flags'])
            self.assertRegex(entry['install_flags'], r'-Sha256 [a-f0-9]{64}$')
            self.assertTrue(entry['cache_dir'])
            self.assertTrue((ROOT / 'php2shell_install/install.cmd').is_file())
            self.assertTrue((ROOT / 'php2shell_install/install.ps1').is_file())
            self.assertEqual(entry['uninstaller'], r'C:\ProgramData\SaltPHP2Shell\install.cmd')
            self.assertFalse(entry['msiexec'])

    def test_x86_does_not_offer_x64_binaries(self):
        for name in ('php83', 'apache24'):
            self.assertIsNone(self.definition(name, 'x86'))

    def test_pillar_and_definitions_agree(self):
        config = yaml.safe_load((ROOT.parent / 'php2shell_lab_windows.pillar.example').read_text())['php2shell']
        for name, target in config['windows']['target_versions'].items():
            self.assertIn(target, self.definition(name)[name])
        self.assertEqual(set(config['windows']['packages']), {'php83', 'apache24'})
        self.assertEqual(config['upload_progress']['ini_files'], [r'C:\SaltLabs\PHP83\php.ini'])
        self.assertEqual(list(config['windows']['services']), ['SaltPHP2ShellApache'])

    def test_deployment_copies_all_required_assets(self):
        deployment = (ROOT / 'deploy-winrepo.sh').read_text()
        for name in ('php83.sls', 'apache24.sls', 'php2shell_install/install.cmd', 'php2shell_install/install.ps1'):
            self.assertIn(name, deployment)
        for name in ('php83', 'apache24'):
            entry = next(iter(self.definition(name)[name].values()))
            self.assertEqual(entry['installer'], 'salt://win/repo-ng/salt-winrepo-ng/_/php2shell_install/install.cmd')


if __name__ == '__main__':
    unittest.main()

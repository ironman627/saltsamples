"""Offline render checks; no package installation or service execution.

Uses Jinja + PyYAML and mocked Salt calls. Native APT/RPM comparisons and live
service/package behavior must still be validated on a Linux canary.
"""
import ast
import json
from pathlib import Path
import re
import unittest

import jinja2
import yaml


ROOT = Path(__file__).resolve().parents[3]
STATE_ROOT = Path(__file__).resolve().parents[1]
PREFIX = "php2shell/"


def regex_search(value, pattern):
    match = re.search(pattern, value)
    return (match.groups() or (match.group(),)) if match else None


def salt_unique(values):
    """Salt's filter accepts one argument, unlike Jinja's builtin unique."""
    result = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def compare(left, right, ignore_epoch=False):
    # Numeric sample fixtures only; deliberately not a substitute for dpkg/rpm.
    def key(version):
        epoch, _, rest = version.rpartition(":")
        return (int(epoch or 0), tuple(map(int, re.findall(r"\d+", rest))))
    return (key(left) > key(right)) - (key(left) < key(right))


def render(state, packages=None, config=None, family="Debian", running=(), comparator=compare, scan=None, pools=None, scan_commands=None, mitigation=None, ini_files=None, os=None, release=None):
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(STATE_ROOT)),
        extensions=["jinja2.ext.do"], undefined=jinja2.StrictUndefined,
    )
    env.filters["regex_search"] = regex_search
    env.filters["unique"] = salt_unique
    calls = []
    # Legacy baseline fixtures isolate the Oct 21 CVEs. Advisory tests pass
    # mitigation={} to exercise the production default (coverage unknown).
    config = dict(config or {})
    config['upload_progress'] = mitigation if mitigation is not None else config.get('upload_progress', {'application_not_affected': True})

    def list_pkgs(**kwargs):
        calls.append("pkg.list_pkgs")
        return packages or {}

    def powershell(command, **kwargs):
        if scan_commands is not None:
            scan_commands.append((command, kwargs))
        return scan if scan is not None else {"runtimes": [], "issues": []}

    def compare_windows(ver1, oper, ver2):
        if not ver1 or not ver2:
            raise ValueError('Salt win_pkg.compare_versions rejects blank versions')
        return compare(ver1, ver2) >= 0 if oper == '>=' else compare(ver1, ver2) < 0

    salt = {
        "pillar.get": lambda name, default: config or default,
        "pkg.list_pkgs": list_pkgs,
        "pkg.version_cmp": comparator,
        "service.status": lambda service: service in running,
        "service.available": lambda service: service in running,
        "pkg.compare_versions": compare_windows,
        "cmd.powershell": powershell,
        "win_iis.list_apppools": lambda: pools or {},
        "win_iis.restart_apppool": lambda name: True,
        "file.file_exists": lambda path: path in (ini_files or {}),
        "file.read": lambda path: ini_files[path],
    }
    result = yaml.safe_load(env.get_template(PREFIX + state + ".sls").render(
        salt=salt, grains={"kernel": "Windows" if family == "Windows" else "Linux", "os_family": family, "id": "canary", "os": os or family, "osrelease": release or ''}, tpldir=PREFIX.rstrip('/'),
    ))
    validate_requisites(result)
    return result, calls


def args(body, function):
    return {key: value for entry in body[function] for key, value in entry.items()}


def validate_requisites(states):
    """Check emitted references as well as YAML syntax after consolidation."""
    for state_id, body in states.items():
        if state_id == 'include':
            continue
        if len(body) != 1:
            raise AssertionError(f'{state_id}: expected a single state function')
        for entry in next(iter(body.values())):
            for key in ['require', 'watch', 'onchanges']:
                for prerequisite in entry.get(key, []):
                    for module, target in prerequisite.items():
                        if target not in states or not any(function.startswith(module + '.') for function in states[target]):
                            raise AssertionError(f'{state_id}: invalid {key}: {module}: {target}')


class RenderTests(unittest.TestCase):
    def assess(self, **kwargs):
        result, calls = render("php2shell_identify", **kwargs)
        data = args(result["php2shell_package_assessment"], "test.configurable_test_state")
        return data, data["comment"], calls

    def test_old_php_and_apache_are_flagged_read_only(self):
        data, report, calls = self.assess(packages={"php8.2-fpm": ["8.2.34-1"], "apache2-bin": ["2.4.68-1"]})
        self.assertFalse(data["result"])
        self.assertFalse(data["changes"])
        self.assertTrue(report.startswith("NEEDS PATCHING"))
        self.assertEqual(calls, ["pkg.list_pkgs"])

    def test_all_four_php_branches(self):
        for branch, fixed in {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}.items():
            with self.subTest(branch=branch):
                data, report, _ = self.assess(packages={f"php{branch}-common": [fixed + "-1"]})
                self.assertTrue(data["result"])
                self.assertTrue(report.startswith("ALREADY PATCHED"))

    def test_vendor_backport_and_epoch(self):
        data, report, _ = self.assess(packages={"php-fpm": ["2:8.2.29-99"]}, config={"minimum_versions": {"php-fpm": "2:8.2.29-98"}})
        self.assertTrue(data["result"])
        self.assertTrue(report.startswith("ALREADY PATCHED"))
        data, report, _ = self.assess(packages={"php-fpm": ["2:8.2.29-99"]})
        self.assertFalse(data["result"])
        self.assertTrue(report.startswith("NEEDS PATCHING"))

    def test_old_or_future_branch_blocks_all_mutation(self):
        for version in ["7.4.33-1", "8.1.33-1", "8.6.0-1"]:
            state, _ = render("php2shell_patch", packages={"php-fpm": [version], "httpd": ["2.4.68-1"]})
            self.assertEqual(list(state), ["php2shell_patch_blocked"])

    def test_eol_vendor_override_can_patch(self):
        state, _ = render("php2shell_patch", packages={"php-fpm": ["7.4.33-1"]}, config={"minimum_versions": {"php-fpm": "7.4.33-99"}})
        self.assertEqual(args(state["php2shell_fixed_packages"], "pkg.installed")["pkgs"], [{"php-fpm": ">=7.4.33-99"}])

    def test_multiple_versions_and_comparison_failure_block(self):
        state, _ = render("php2shell_patch", packages={"php-cli": ["8.2.34-1", "8.2.35-1"]})
        self.assertIn("php2shell_patch_blocked", state)
        state, _ = render("php2shell_patch", packages={"php-cli": ["8.2.34-1"]}, comparator=lambda *a, **k: None)
        self.assertIn("php2shell_patch_blocked", state)

    def test_unsupported_and_absent_inventory(self):
        state, calls = render("php2shell_patch", family="Darwin")
        self.assertIn("php2shell_patch_blocked", state)
        self.assertEqual(calls, [])
        state, _ = render("php2shell_patch")
        self.assertIn("php2shell_no_packaged_runtime", state)

    def test_metapackages_are_skipped_but_mod_php_is_found(self):
        _, report, _ = self.assess(packages={"php": ["2:8.2+93"], "php-fpm": ["2:8.2+93"], "libapache2-mod-php8.2": ["8.2.34-1"]})
        self.assertTrue(report.startswith("NEEDS PATCHING"))

    def test_ubuntu_php_common_utilities_do_not_block_runtime_patching(self):
        packages = {'php-common': ['2:93ubuntu2'], 'php-fpm': ['2:8.3+93ubuntu2'], 'php8.3-common': ['8.3.36-0ubuntu0.24.04.1'], 'php8.3-cli': ['8.3.36-0ubuntu0.24.04.1'], 'php8.3-fpm': ['8.3.36-0ubuntu0.24.04.1']}
        state, _ = render('php2shell_patch', packages=packages)
        self.assertNotIn('php2shell_patch_blocked', state)
        selected = args(state['php2shell_fixed_packages'], 'pkg.installed')['pkgs']
        self.assertEqual({next(iter(item)) for item in selected}, {'php8.3-common', 'php8.3-cli', 'php8.3-fpm'})

    def test_debian_php_common_alone_does_not_indicate_runtime(self):
        for version in ['2:93ubuntu2', '2:96']:
            data, comment, _ = self.assess(packages={'php-common': [version]})
            self.assertTrue(data['result'])
            self.assertTrue(comment.startswith('NOT EXPOSED'))

    def test_redhat_php_common_still_requires_runtime_security_floor(self):
        state, _ = render('php2shell_patch', family='RedHat', packages={'php-common': ['8.3.35-1.el9']})
        self.assertEqual(args(state['php2shell_fixed_packages'], 'pkg.installed')['pkgs'], [{'php-common': '>=8.3.36'}])
        data, comment, _ = self.assess(family='RedHat', packages={'php-common': ['8.3.35-1.el9']})
        self.assertFalse(data['result'])
        self.assertTrue(comment.startswith('NEEDS PATCHING'))

    def test_ubuntu_versioned_common_retains_security_check(self):
        data, comment, _ = self.assess(packages={'php-common': ['2:93ubuntu2'], 'php8.3-common': ['8.3.35-1']})
        self.assertFalse(data['result'])
        self.assertTrue(comment.startswith('NEEDS PATCHING'))

    def test_ubuntu_noble_uses_verified_backport_for_all_runtime_packages(self):
        names = ['php8.3-cli', 'php8.3-common', 'php8.3-fpm', 'php8.3-opcache', 'libapache2-mod-php8.3']
        packages = {name: ['8.3.6-0ubuntu0.24.04.13'] for name in names}
        state, _ = render('php2shell_patch', packages=packages, os='Ubuntu', release='24.04')
        self.assertEqual(args(state['php2shell_fixed_packages'], 'pkg.installed')['pkgs'], [{name: '>=8.3.6-0ubuntu0.24.04.13'} for name in sorted(names)])

    def test_ubuntu_mitigated_demonstration_uses_backported_packages(self):
        path = '/etc/php/8.3/fpm/php.ini'
        policy = {'ini_files': [path], 'configuration_complete': True}
        for version, value, expected in [('8.3.6-0ubuntu0.24.04.12', '0', 'NEEDS PATCHING'), ('8.3.6-0ubuntu0.24.04.13', '1', 'NEEDS MITIGATION'), ('8.3.6-0ubuntu0.24.04.13', '0', 'MITIGATED')]:
            data, comment, _ = self.assess(packages={'php8.3-fpm': [version]}, os='Ubuntu', release='24.04', mitigation=policy, ini_files={path: 'session.upload_progress.enabled=' + value})
            self.assertTrue(comment.startswith(expected))
            self.assertEqual(data['result'], expected == 'MITIGATED')

    def test_ubuntu_vendor_default_does_not_certify_custom_or_other_distro_builds(self):
        for os, release, version in [('Ubuntu', '24.04', '8.3.35-1ubuntu-ppa1'), ('Ubuntu', '24.04', '8.3.6-1ubuntu-ppa1'), ('Ubuntu', '24.04', '8.3.6-0ubuntu0.24.04.13+ppa1'), ('Ubuntu', '24.04', '8.3.6-0maysync1'), ('Debian', '24.04', '8.3.6-0ubuntu0.24.04.13'), ('Ubuntu', '22.04', '8.3.6-0ubuntu0.24.04.13')]:
            state, _ = render('php2shell_patch', packages={'php8.3-fpm': [version]}, os=os, release=release)
            self.assertEqual(args(state['php2shell_fixed_packages'], 'pkg.installed')['pkgs'], [{'php8.3-fpm': '>=8.3.36'}])

    def test_ubuntu_vendor_baseline_can_be_overridden_or_disabled(self):
        packages = {'php8.3-fpm': ['8.3.6-0ubuntu0.24.04.13']}
        for config, expected in [({'use_vendor_baselines': False}, '8.3.36'), ({'minimum_versions': {'php8.3-fpm': '8.3.6-0ubuntu0.24.04.14'}}, '8.3.6-0ubuntu0.24.04.14')]:
            state, _ = render('php2shell_patch', packages=packages, os='Ubuntu', release='24.04', config=config)
            self.assertEqual(args(state['php2shell_fixed_packages'], 'pkg.installed')['pkgs'], [{'php8.3-fpm': '>=' + expected}])

    def test_all_supported_ubuntu_backport_baselines(self):
        for release, package, fixed in [('22.04', 'php8.1-fpm', '8.1.2-1ubuntu2.28'), ('24.04', 'php8.3-fpm', '8.3.6-0ubuntu0.24.04.13'), ('26.04', 'php8.5-fpm', '8.5.4-0ubuntu1.5'), ('26.10', 'php8.5-fpm', '8.5.9-0ubuntu2.1')]:
            state, _ = render('php2shell_patch', packages={package: [fixed]}, os='Ubuntu', release=release)
            self.assertEqual(args(state['php2shell_fixed_packages'], 'pkg.installed')['pkgs'], [{package: '>=' + fixed}])

    def test_running_fpm_and_apache_restart_with_config_checks(self):
        state, _ = render("php2shell_patch", packages={"php8.2-fpm": ["8.2.34-1"], "apache2": ["2.4.68-1"]}, running=["apache2", "php8.2-fpm"])
        pkg = args(state["php2shell_fixed_packages"], "pkg.installed")
        self.assertFalse(pkg["skip_verify"])
        self.assertFalse(pkg["ignore_epoch"])
        checks = [dict((key, value) for entry in args(body, "module.run")["cmd.run_all"] for key, value in entry.items()) for state_id, body in state.items() if state_id.startswith("php2shell_configtest_")]
        self.assertEqual([check["cmd"] for check in checks], [["apache2ctl", "configtest"], ["php-fpm8.2", "-t"]])
        for check in checks:
            self.assertIs(check["python_shell"], False)
            # Binding the rendered arguments catches duplicate/misspelled
            # keyword arguments without executing an OS command.
            def run_all(cmd, python_shell=None):
                return cmd, python_shell
            self.assertEqual(run_all(**check), (check["cmd"], False))
        for body in state.values():
            if "service.running" in body:
                self.assertIn({"pkg": "php2shell_fixed_packages"}, args(body, "service.running")["watch"])
                self.assertTrue(any("module" in req for req in args(body, "service.running")["require"]))

    def test_stopped_units_are_not_started(self):
        state, _ = render("php2shell_patch", packages={"php-fpm": ["8.2.34-1"], "httpd": ["2.4.68-1"]}, family="RedHat")
        self.assertEqual(list(state), ["php2shell_fixed_packages", "php2shell_apache_repository_updates", "php2shell_upload_progress"])

    def test_rocky_apache_uses_repository_updates_without_false_compliance(self):
        packages = {name: ["2.4.62-13.el9_8.5"] for name in ["httpd", "httpd-core", "httpd-tools"]}
        state, _ = render("php2shell_patch", packages=packages, family="RedHat", running=["httpd"])
        self.assertNotIn("php2shell_fixed_packages", state)
        updates = args(state["php2shell_apache_repository_updates"], "pkg.latest")
        self.assertEqual(set(updates["pkgs"]), set(packages))
        self.assertEqual(args(state["php2shell_restart_1"], "service.running")["watch"], [{"pkg": "php2shell_apache_repository_updates"}])
        data, report, _ = self.assess(packages=packages, family="RedHat")
        self.assertTrue(data["result"])
        self.assertTrue(report.startswith("NOT EXPOSED"))

    def test_apache_does_not_affect_php2shell_status(self):
        for strict in [False, True]:
            state, _ = render("php2shell_identify", packages={"httpd": ["2.4.62-13.el9_8.6"], "php-fpm": ["8.2.35-1"]}, config={"require_apache_baseline": strict})
            php = args(state["php2shell_package_assessment"], "test.configurable_test_state")
            self.assertTrue(php["result"])
            self.assertTrue(php["comment"].startswith("ALREADY PATCHED"))
            self.assertEqual(len(state), 1)

    def test_explicit_apache_failure_does_not_fail_php_assessment(self):
        state, _ = render("php2shell_identify", packages={"httpd": ["2.4.62-13.el9_8.5"]}, config={"minimum_versions": {"httpd": "2.4.62-13.el9_8.6"}})
        self.assertTrue(args(state["php2shell_package_assessment"], "test.configurable_test_state")["result"])
        self.assertEqual(len(state), 1)

    def test_unknown_php_baseline_is_not_reported_patched(self):
        data, comment, _ = self.assess(packages={"php-fpm": ["7.4.33-1"]})
        self.assertFalse(data["result"])
        self.assertTrue(comment.startswith("NEEDS PATCHING"))

    def test_unsupported_platform_is_not_reported_unexposed(self):
        data, comment, _ = self.assess(family="Darwin")
        self.assertFalse(data["result"])
        self.assertTrue(comment.startswith("UNDETERMINED"))

    def test_multiple_installed_php_versions_require_review(self):
        data, comment, _ = self.assess(packages={"php-fpm": ["8.2.35-1", "8.2.36-1"]})
        self.assertFalse(data["result"])
        self.assertTrue(comment.startswith("NEEDS PATCHING"))

    def test_empty_package_versions_do_not_claim_unexposed(self):
        for family in ['Debian', 'Windows']:
            data, comment, _ = self.assess(packages={'php': []}, family=family)
            self.assertFalse(data['result'])
            self.assertTrue(comment.startswith('NEEDS PATCHING'))

    def test_windows_missing_installed_version_blocks_before_comparison(self):
        for package, target in [('php', '8.3.36'), ('httpd', '2.4.69')]:
            config = {'windows': {'target_versions': {package: target}, 'no_web_workers': True}}
            state, _ = render('php2shell_windows_patch', family='Windows', packages={package: []}, config=config)
            self.assertEqual(list(state), ['php2shell_windows_patch_blocked'])

    def test_mapping_is_not_accepted_as_config_test_argv(self):
        config = {'services': {'php-fpm': {'command': 'php-fpm -t'}}}
        state, _ = render('php2shell_patch', packages={'php-fpm': ['8.3.35']}, config=config)
        self.assertEqual(list(state), ['php2shell_patch_blocked'])
        config = {'windows': {'services': {'Apache2.4': {'command': 'httpd -t'}}}}
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'php': ['8.3.35']}, config=config)
        self.assertEqual(list(state), ['php2shell_windows_patch_blocked'])

    def test_shared_services_preserve_state_ids_and_skip_stopped_units(self):
        config = {'services': {'a-stopped': ['check-a'], 'b-running': ['check-b']}}
        state, _ = render('php2shell_patch', packages={'php-cli': ['8.3.35']}, config=config, running=['b-running'])
        self.assertNotIn('php2shell_configtest_1', state)
        self.assertIn('php2shell_configtest_2', state)
        config = {'windows': {'target_versions': {'php': '8.3.36'}, 'services': {'Apache2.4': ['httpd.exe', '-t']}}}
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'php': ['8.3.35']}, config=config, running=['Apache2.4'])
        self.assertIn('php2shell_windows_configtest_1', state)
        self.assertIn('php2shell_windows_restart_1', state)
        self.assertIn('php2shell_windows_running_1', state)

    def test_apache_vendor_minimum_is_enforced(self):
        packages = {"httpd": ["2.4.62-13.el9_8.5"]}
        config = {"minimum_versions": {"httpd": "2.4.62-13.el9_8.6"}}
        state, _ = render("php2shell_patch", packages=packages, config=config, family="RedHat")
        self.assertEqual(args(state["php2shell_fixed_packages"], "pkg.installed")["pkgs"], [{"httpd": ">=2.4.62-13.el9_8.6"}])
        self.assertNotIn("php2shell_apache_repository_updates", state)

    def test_fpm_does_not_require_apache_repository_update(self):
        state, _ = render("php2shell_patch", packages={"php-fpm": ["8.2.34-1"], "httpd": ["2.4.62-13.el9_8.5"]}, family="RedHat", running=["httpd", "php-fpm"])
        fpm = args(state["php2shell_restart_2"], "service.running")
        self.assertEqual(fpm["watch"], [{"pkg": "php2shell_fixed_packages"}])

    def test_import_uses_php2shell_fileserver_directory(self):
        from tempfile import TemporaryDirectory
        from shutil import copyfile
        with TemporaryDirectory() as directory:
            deployed = Path(directory) / "php2shell"
            deployed.mkdir()
            for name in [p.name for p in (STATE_ROOT / PREFIX).iterdir() if p.suffix in ['.sls', '.jinja']]:
                copyfile(STATE_ROOT / PREFIX / name, deployed / name)
            env = jinja2.Environment(loader=jinja2.FileSystemLoader(directory), extensions=["jinja2.ext.do"])
            env.filters["regex_search"] = regex_search
            env.filters["unique"] = salt_unique
            salt = {"pillar.get": lambda *args: {}, "pkg.list_pkgs": lambda **kwargs: {}, "cmd.powershell": lambda *a, **k: {'runtimes': [], 'issues': []}}
            for family in ['RedHat', 'Windows']:
                for name in ["php2shell_identify", "php2shell_patch", "php2shell_windows_patch"] if family == 'Windows' else ["php2shell_identify", "php2shell_patch"]:
                    result = yaml.safe_load(env.get_template("php2shell/" + name + ".sls").render(salt=salt, tpldir="unrelated/caller", grains={"kernel": "Windows" if family == 'Windows' else "Linux", "os_family": family}))
                    self.assertTrue(result)

    def test_extra_packages_and_custom_service(self):
        config = {"extra_php_packages": ["custom-php"], "minimum_versions": {"custom-php": "8.3.36-1"}, "services": {"custom-unit": ["/opt/php/fpm", "-t"]}, "force_restart": True, "fromrepo": "security"}
        state, _ = render("php2shell_patch", packages={"custom-php": ["8.3.35-1"]}, config=config, running=["custom-unit"])
        self.assertEqual(args(state["php2shell_fixed_packages"], "pkg.installed")["fromrepo"], "security")
        restart = args(state["php2shell_restart_1"], "module.run")
        self.assertEqual(restart["service.restart"], [{"name": "custom-unit"}])

    def test_shell_string_config_test_is_rejected(self):
        state, _ = render("php2shell_patch", packages={"php-fpm": ["8.2.34-1"]}, config={"services": {"php-fpm": "php-fpm -t; unsafe"}})
        self.assertEqual(list(state), ["php2shell_patch_blocked"])

    def test_salt_module_run_checks_command_exit_status(self):
        # Exercise Salt's real result interpretation without importing the
        # full loader or starting a minion. The repository includes Salt source.
        source = ROOT / "custom_modules/default_modules/salt/states/module.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ["_get_result", "_get_dict_result"]]
        self.assertEqual(len(helpers), 2)
        namespace = {}
        exec(compile(ast.Module(body=helpers, type_ignores=[]), str(source), "exec"), namespace)
        check = namespace["_get_result"]
        self.assertTrue(check({"retcode": 0, "stdout": "", "stderr": "Syntax OK"}))
        self.assertFalse(check({"retcode": 1, "stdout": "", "stderr": "Syntax error"}))

    def test_windows_dispatch(self):
        state, _ = render('php2shell_patch', family='Windows')
        self.assertEqual(state, {'include': ['php2shell.php2shell_windows_patch']})

    def test_lab_install_requires_explicit_enablement(self):
        state, _ = render('php2shell_lab_install', family='RedHat')
        self.assertEqual(list(state), ['php2shell_lab_install_blocked'])

    def test_lab_rocky_packages_and_optional_services(self):
        state, _ = render('php2shell_lab_install', family='RedHat', config={'lab': {'enabled': True}})
        packages = args(state['php2shell_lab_packages'], 'pkg.latest')
        self.assertEqual(packages['pkgs'], ['httpd', 'php', 'php-cli', 'php-common', 'php-fpm'])
        self.assertFalse(packages['skip_verify'])
        self.assertEqual(list(state), ['php2shell_lab_packages'])
        state, _ = render('php2shell_lab_install', family='RedHat', config={'lab': {'enabled': True, 'start_services': True}})
        self.assertEqual(args(state['php2shell_lab_service_1'], 'service.running')['name'], 'php-fpm')
        self.assertEqual(args(state['php2shell_lab_service_2'], 'service.running')['name'], 'httpd')

    def test_lab_debian_uses_explicit_branch(self):
        state, _ = render('php2shell_lab_install', config={'lab': {'enabled': True}})
        self.assertIn('php2shell_lab_install_blocked', state)
        state, _ = render('php2shell_lab_install', config={'lab': {'enabled': True, 'php_branch': '8.3', 'start_services': True}})
        self.assertIn('php8.3-fpm', args(state['php2shell_lab_packages'], 'pkg.latest')['pkgs'])
        self.assertEqual(args(state['php2shell_lab_service_1'], 'service.running')['name'], 'php8.3-fpm')

    def test_lab_exact_package_versions_and_mitigation_reset(self):
        config = {'lab': {'enabled': True, 'start_services': True, 'exercise_mitigation': True, 'package_versions': {'php-fpm': '8.3.35-1'}}}
        state, _ = render('php2shell_lab_install', family='RedHat', config=config, mitigation={'ini_files': ['/etc/php.ini']})
        self.assertIn({'php-fpm': '8.3.35-1'}, args(state['php2shell_lab_packages'], 'pkg.installed')['pkgs'])
        setting = args(state['php2shell_lab_upload_progress_1'], 'file.replace')
        self.assertEqual(setting['repl'], 'session.upload_progress.enabled = 1')
        self.assertEqual(setting['require'], [{'file': 'php2shell_lab_php_ini_1'}])
        managed = args(state['php2shell_lab_php_ini_1'], 'file.managed')
        self.assertEqual(managed['source'], 'salt://php2shell/files/php.ini')
        self.assertFalse(managed['replace'])
        self.assertEqual(managed['require'], [{'pkg': 'php2shell_lab_packages'}])
        self.assertTrue((STATE_ROOT / 'php2shell/files/php.ini').is_file())
        self.assertIn({'file': 'php2shell_lab_upload_progress_1'}, args(state['php2shell_lab_service_1'], 'service.running')['watch'])

    def test_lab_latest_can_be_disabled_for_install_only(self):
        state, _ = render('php2shell_lab_install', family='RedHat', config={'lab': {'enabled': True, 'install_latest': False}})
        self.assertIn('pkg.installed', state['php2shell_lab_packages'])

    def test_lab_default_latest_then_mitigation_demonstration(self):
        path = '/etc/php/8.3/fpm/php.ini'
        config = {'lab': {'enabled': True, 'php_branch': '8.3', 'exercise_mitigation': True, 'start_services': True}}
        policy = {'ini_files': [path], 'configuration_complete': True, 'application_not_affected': False}
        install, _ = render('php2shell_lab_install', config=config, mitigation=policy)
        self.assertIn('pkg.latest', install['php2shell_lab_packages'])
        reset = args(install['php2shell_lab_upload_progress_1'], 'file.replace')['repl']
        data, comment, _ = self.assess(packages={'php8.3-fpm': ['8.3.36']}, mitigation=policy, ini_files={path: reset})
        self.assertFalse(data['result'])
        self.assertTrue(comment.startswith('NEEDS MITIGATION'))
        patch, _ = render('php2shell_patch', packages={'php8.3-fpm': ['8.3.36']}, running=['php8.3-fpm'], mitigation=policy, ini_files={path: reset})
        applied = args(patch['php2shell_upload_progress_1'], 'file.replace')['repl']
        data, comment, _ = self.assess(packages={'php8.3-fpm': ['8.3.36']}, mitigation=policy, ini_files={path: applied})
        self.assertTrue(data['result'])
        self.assertTrue(comment.startswith('MITIGATED'))

    def test_lab_windows_ini_seed_omits_unix_permissions(self):
        config = {'lab': {'enabled': True, 'packages': ['company-php'], 'package_versions': {'company-php': '8.3.36'}, 'exercise_mitigation': True}}
        state, _ = render('php2shell_lab_install', family='Windows', config=config, mitigation={'ini_files': [r'C:\PHP\php.ini']})
        managed = args(state['php2shell_lab_php_ini_1'], 'file.managed')
        self.assertEqual(managed['source'], 'salt://php2shell/files/php.ini')
        self.assertNotIn('mode', managed)
        self.assertNotIn('user', managed)

    def test_lab_windows_requires_real_package_names_and_supports_pins(self):
        state, _ = render('php2shell_lab_install', family='Windows', config={'lab': {'enabled': True}})
        self.assertIn('php2shell_lab_install_blocked', state)
        config = {'lab': {'enabled': True, 'packages': ['company-php'], 'package_versions': {'company-php': '8.3.35'}, 'start_services': True, 'services': ['Apache2.4']}}
        state, _ = render('php2shell_lab_install', family='Windows', config=config)
        self.assertEqual(args(state['php2shell_lab_packages'], 'pkg.installed')['pkgs'], [{'company-php': '8.3.35'}])

    def test_lab_windows_latest_reuses_remediation_mappings(self):
        config = {
            'lab': {'enabled': True, 'start_services': True, 'exercise_mitigation': True},
            'windows': {'packages': {'company-php': 'php', 'company-apache': 'apache'},
                        'services': {'Apache2.4': [r'C:\Apache\bin\httpd.exe', '-t']}},
        }
        state, _ = render('php2shell_lab_install', family='Windows', config=config,
                          mitigation={'ini_files': [r'C:\PHP\php.ini']})
        packages = args(state['php2shell_lab_packages'], 'pkg.latest')
        self.assertEqual(packages['pkgs'], ['company-php', 'company-apache'])
        self.assertNotIn('skip_verify', packages)
        service = args(state['php2shell_lab_service_1'], 'service.running')
        self.assertEqual(service['name'], 'Apache2.4')
        self.assertIn({'file': 'php2shell_lab_upload_progress_1'}, service['watch'])

    def test_lab_windows_explicit_overrides_and_install_only(self):
        config = {'lab': {'enabled': True, 'install_latest': False,
                          'packages': ['alternate-php'], 'services': ['LabApache'], 'start_services': True},
                  'windows': {'packages': {'unused-php': 'php'}, 'services': {'UnusedApache': ['test']}}}
        state, _ = render('php2shell_lab_install', family='Windows', config=config)
        self.assertEqual(args(state['php2shell_lab_packages'], 'pkg.installed')['pkgs'], ['alternate-php'])
        self.assertEqual(args(state['php2shell_lab_service_1'], 'service.running')['name'], 'LabApache')

    def test_lab_windows_rejects_invalid_pin_and_missing_startup_service(self):
        for lab in [
            {'package_versions': {'php': 'latest'}},
            {'package_versions': ['8.3.36']},
            {'start_services': True},
        ]:
            config = {'lab': dict({'enabled': True, 'packages': ['php']}, **lab)}
            state, _ = render('php2shell_lab_install', family='Windows', config=config)
            self.assertEqual(list(state), ['php2shell_lab_install_blocked'])

    def test_lab_windows_example_renders(self):
        config = yaml.safe_load((STATE_ROOT / 'php2shell/php2shell_lab_windows.pillar.example').read_text())['php2shell']
        state, _ = render('php2shell_lab_install', family='Windows', config=config)
        self.assertEqual(args(state['php2shell_lab_packages'], 'pkg.installed')['pkgs'],
                         [{'php83': '8.3.36.1'}, {'apache24': '2.4.69'}])
        self.assertEqual(args(state['php2shell_lab_service_1'], 'service.running')['name'], 'SaltPHP2ShellApache')
        self.assertEqual(args(state['php2shell_lab_php_ini_1'], 'file.managed')['name'], r'C:\SaltLabs\PHP83\php.ini')

    def test_lab_windows_target_versions_and_lab_pin_precedence(self):
        config = {'lab': {'enabled': True, 'package_versions': {'php83': '8.3.35'}},
                  'windows': {'packages': {'php83': 'php', 'apache24': 'apache'},
                              'target_versions': {'php83': '8.3.36.1', 'apache24': '2.4.69', 'unused': '1.0.0'}}}
        state, _ = render('php2shell_lab_install', family='Windows', config=config)
        self.assertEqual(args(state['php2shell_lab_packages'], 'pkg.installed')['pkgs'],
                         [{'php83': '8.3.35'}, {'apache24': '2.4.69'}])
        config['lab']['packages'] = ['apache24']
        state, _ = render('php2shell_lab_install', family='Windows', config=config)
        self.assertEqual(args(state['php2shell_lab_packages'], 'pkg.installed')['pkgs'], [{'apache24': '2.4.69'}])

    def test_lab_windows_rejects_invalid_target_versions(self):
        for targets in [['8.3.36.1'], {'php83': 'latest'}]:
            config = {'lab': {'enabled': True},
                      'windows': {'packages': {'php83': 'php'}, 'target_versions': targets}}
            state, _ = render('php2shell_lab_install', family='Windows', config=config)
            self.assertEqual(list(state), ['php2shell_lab_install_blocked'])

    def test_lab_mitigation_exercise_rejects_user_ini(self):
        state, _ = render('php2shell_lab_install', family='RedHat', config={'lab': {'enabled': True, 'exercise_mitigation': True}}, mitigation={'ini_files': ['/var/www/.user.ini']})
        self.assertEqual(list(state), ['php2shell_lab_install_blocked'])

    def test_new_advisory_requires_configuration_review_by_default(self):
        for family in ['Debian', 'Windows']:
            data, comment, _ = self.assess(family=family, packages={'php': ['8.3.36']}, mitigation={})
            self.assertFalse(data['result'])
            self.assertTrue(comment.startswith('UNDETERMINED'))
            self.assertIn('CVE-2026-115560', comment)

    def test_upload_progress_assessment_accepts_disabled_values(self):
        path = '/etc/php.ini'
        policy = {'ini_files': [path], 'configuration_complete': True}
        for value in ['0', 'Off', 'false', 'no', '0 ; mitigation']:
            data, comment, _ = self.assess(packages={'php': ['8.3.36']}, mitigation=policy, ini_files={path: 'session.upload_progress.enabled = ' + value + '\n'})
            self.assertTrue(data['result'])
            self.assertTrue(comment.startswith('MITIGATED'))
            self.assertNotIn('ALREADY PATCHED', comment)

    def test_upload_progress_enabled_missing_or_conflicting_needs_mitigation(self):
        path = '/etc/php.ini'
        policy = {'ini_files': [path], 'configuration_complete': True}
        for contents in ['session.upload_progress.enabled = On\n', ';session.upload_progress.enabled = 0\n', 'session.upload_progress.enabled=0\nsession.upload_progress.enabled=1\n']:
            data, comment, _ = self.assess(packages={'php-fpm': ['8.3.36']}, mitigation=policy, ini_files={path: contents})
            self.assertFalse(data['result'])
            self.assertTrue(comment.startswith('NEEDS MITIGATION'))

    def test_upload_progress_missing_file_is_not_mitigated(self):
        data, comment, _ = self.assess(packages={'php-fpm': ['8.3.36']}, mitigation={'ini_files': ['/missing/php.ini'], 'configuration_complete': True})
        self.assertFalse(data['result'])
        self.assertTrue(comment.startswith('UNDETERMINED'))

    def test_upload_progress_rejects_wrong_configuration_scope(self):
        for path in ['/var/www/.user.ini', '/etc/php-fpm.d/www.conf']:
            state, _ = render('php2shell_patch', packages={'php-fpm': ['8.3.36']}, mitigation={'ini_files': [path], 'configuration_complete': True}, ini_files={path: 'session.upload_progress.enabled=0'})
            self.assertIn('test.fail_without_changes', state['php2shell_upload_progress'])
            self.assertNotIn('php2shell_upload_progress_1', state)

    def test_linux_mitigation_keeps_case_distinct_ini_paths(self):
        paths = ['/etc/php.ini', '/etc/PHP.ini']
        data, comment, _ = self.assess(packages={'php-fpm': ['8.3.36']}, mitigation={'ini_files': paths, 'configuration_complete': True}, ini_files={paths[0]: 'session.upload_progress.enabled=0', paths[1]: 'session.upload_progress.enabled=On'})
        self.assertFalse(data['result'])
        self.assertTrue(comment.startswith('NEEDS MITIGATION'))

    def test_windows_mitigation_deduplicates_case_variants(self):
        path = r'C:\PHP\php.ini'
        data, comment, _ = self.assess(family='Windows', packages={'php': ['8.3.36']}, mitigation={'ini_files': [path, path.lower()], 'configuration_complete': True}, ini_files={path: 'session.upload_progress.enabled=0'})
        self.assertTrue(data['result'])
        self.assertTrue(comment.startswith('MITIGATED'))

    def test_duplicate_ini_path_emits_one_file_state(self):
        path = '/etc/php.ini'
        state, _ = render('php2shell_patch', packages={'php-fpm': ['8.3.36']}, running=['php-fpm'], mitigation={'ini_files': [path, path], 'configuration_complete': True}, ini_files={path: 'session.upload_progress.enabled=On'})
        self.assertIn('php2shell_upload_progress_1', state)
        self.assertNotIn('php2shell_upload_progress_2', state)

    def test_linux_mitigation_files_gate_configuration_and_restart(self):
        path = '/etc/php.ini'
        state, _ = render('php2shell_patch', packages={'php-fpm': ['8.3.36']}, running=['php-fpm'], mitigation={'ini_files': [path], 'configuration_complete': True}, ini_files={path: 'session.upload_progress.enabled = On\n'})
        replacement = args(state['php2shell_upload_progress_1'], 'file.replace')
        self.assertTrue(replacement['append_if_not_found'])
        self.assertEqual(replacement['require'], [{'pkg': 'php2shell_fixed_packages'}])
        watcher = args(state['php2shell_restart_1'], 'service.running')
        self.assertIn({'file': 'php2shell_upload_progress_1'}, watcher['watch'])
        check = args(state['php2shell_configtest_1'], 'module.run')
        self.assertIn({'test': 'php2shell_upload_progress'}, check['require'])
        source = 'memory_limit=128M\r\nsession.upload_progress.enabled=On\r\nsession.upload_progress.enabled=1\r\n'
        patched = re.sub(replacement['pattern'], replacement['repl'], source)
        self.assertEqual(patched.count('session.upload_progress.enabled = 0'), 2)
        self.assertIn('memory_limit=128M\r\n', patched)
        self.assertEqual(re.sub(replacement['pattern'], replacement['repl'], patched), patched)

    def test_windows_mitigation_recycles_iis_without_package_upgrade(self):
        path = r'C:\PHP\php.ini'
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'php': ['8.3.36']}, config={'windows': {'iis_apppools': ['PHP-Pool']}}, pools={'PHP-Pool': {'state': 'Started'}}, mitigation={'ini_files': [path], 'configuration_complete': True}, ini_files={path: 'session.upload_progress.enabled=On'})
        self.assertIn('test.nop', state['php2shell_windows_fixed_packages'])
        self.assertIn('file.replace', state['php2shell_upload_progress_1'])
        restart = args(state['php2shell_windows_iis_pool_1'], 'module.run')
        self.assertIn({'file': 'php2shell_upload_progress_1'}, restart['require'])

    def test_mitigation_requires_worker_strategy_and_coverage(self):
        path = '/etc/php.ini'
        state, _ = render('php2shell_patch', packages={'php-cli': ['8.3.36']}, mitigation={'ini_files': [path], 'configuration_complete': True}, ini_files={path: 'session.upload_progress.enabled=On'})
        self.assertIn('test.fail_without_changes', state['php2shell_upload_progress'])
        self.assertNotIn('php2shell_upload_progress_1', state)
        state, _ = render('php2shell_patch', packages={'php-fpm': ['8.3.36']}, mitigation={'ini_files': [path]}, ini_files={path: 'session.upload_progress.enabled=0'})
        self.assertIn('test.fail_without_changes', state['php2shell_upload_progress'])

    def test_old_vulnerability_still_needs_patching_with_mitigation(self):
        path = '/etc/php.ini'
        data, comment, _ = self.assess(packages={'php-fpm': ['8.3.35']}, mitigation={'ini_files': [path], 'configuration_complete': True}, ini_files={path: 'session.upload_progress.enabled=0'})
        self.assertFalse(data['result'])
        self.assertTrue(comment.startswith('NEEDS PATCHING'))

    def test_linux_apache_php_module_is_patched_and_apache_watches_php(self):
        for family, module, apache, service in [('Debian', 'libapache2-mod-php8.3', 'apache2', 'apache2'), ('Suse', 'apache2-mod_php8', 'apache2', 'apache2'), ('RedHat', 'mod_php83', 'httpd', 'httpd')]:
            with self.subTest(family=family):
                packages = {module: ['8.3.35'], apache: ['2.4.62']}
                _, comment, _ = self.assess(packages=packages, family=family)
                self.assertTrue(comment.startswith('NEEDS PATCHING'))
                state, _ = render('php2shell_patch', packages=packages, family=family, running=[service])
                self.assertIn({module: '>=8.3.36'}, args(state['php2shell_fixed_packages'], 'pkg.installed')['pkgs'])
                self.assertIn({'pkg': 'php2shell_fixed_packages'}, args(state['php2shell_restart_1'], 'service.running')['watch'])

    def test_windows_apache_module_cannot_use_iis_only_restart(self):
        runtime = r'C:\PHP\php8apache2_4.dll'
        scan = {'runtimes': [{'path': runtime, 'component': 'php', 'version': '8.3.35'}], 'issues': []}
        config = {'windows': {'packages': {'company-php': 'php'}, 'runtime_packages': {runtime: 'company-php'}, 'target_versions': {'company-php': '8.3.36'}, 'iis_apppools': ['PHP-Pool']}}
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'company-php': ['8.3.35']}, config=config, scan=scan, pools={'PHP-Pool': {'state': 'Started'}})
        self.assertIn('php2shell_windows_patch_blocked', state)
        config['windows']['services'] = {'Apache2.4': [r'C:\Apache24\bin\httpd.exe', '-t']}
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'company-php': ['8.3.35']}, config=config, scan=scan, running=['Apache2.4'], pools={'PHP-Pool': {'state': 'Started'}})
        self.assertIn('php2shell_windows_restart_1', state)

    def test_windows_package_statuses(self):
        for version, expected in [('8.3.35', 'NEEDS PATCHING'), ('8.3.36', 'ALREADY PATCHED')]:
            data, comment, _ = self.assess(family='Windows', packages={'php': [version]})
            self.assertTrue(comment.startswith(expected))
            self.assertEqual(data['result'], expected == 'ALREADY PATCHED')
        _, comment, _ = self.assess(family='Windows')
        self.assertTrue(comment.startswith('NOT EXPOSED'))

    def test_windows_portable_runtime_detected(self):
        for version, expected in [('8.3.35', 'NEEDS PATCHING'), ('8.3.36', 'ALREADY PATCHED')]:
            scan = {'runtimes': [{'path': r'C:\custom\php-cgi.exe', 'component': 'php', 'version': version}], 'issues': []}
            _, comment, _ = self.assess(family='Windows', scan=scan)
            self.assertTrue(comment.startswith(expected))
            state, _ = render('php2shell_windows_patch', family='Windows', scan=scan)
            self.assertIn('php2shell_windows_patch_blocked', state)

    def test_windows_unknown_scan_does_not_claim_unexposed(self):
        for scan in [{}, {'runtimes': [], 'issues': ['Access denied']}, {'runtimes': [{'path': r'C:\PHP\php.exe', 'component': 'php', 'version': ''}], 'issues': []}]:
            data, comment, _ = self.assess(family='Windows', scan=scan)
            self.assertFalse(data['result'])
            self.assertTrue(comment.startswith('UNDETERMINED'))

    def test_windows_malformed_scan_is_reported_without_render_failure(self):
        for scan in [{'runtimes': {}, 'issues': []}, {'runtimes': None, 'issues': []}, {'runtimes': 'invalid', 'issues': []}, {'runtimes': [], 'issues': 'Access denied'}, {'runtimes': [{}], 'issues': []}, {'runtimes': ['invalid'], 'issues': []}]:
            with self.subTest(scan=scan):
                data, comment, _ = self.assess(family='Windows', scan=scan)
                self.assertFalse(data['result'])
                self.assertTrue(comment.startswith('UNDETERMINED'))
                state, _ = render('php2shell_windows_patch', family='Windows', scan=scan)
                self.assertIn('php2shell_windows_patch_blocked', state)

    def test_windows_runtime_owners_are_case_insensitive(self):
        config = {'windows': {'packages': {'company-php': 'php'}, 'target_versions': {'company-php': '8.3.36'}, 'runtime_packages': {r'c:\PHP\PHP-CGI.EXE': 'company-php'}, 'no_web_workers': True}}
        scan = {'runtimes': [{'path': r'C:\php\php-cgi.exe', 'component': 'php', 'version': '8.3.35'}], 'issues': []}
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'company-php': ['8.3.35']}, config=config, scan=scan)
        self.assertIn('pkg.installed', state['php2shell_windows_fixed_packages'])

    def test_windows_only_entrypoint_fails_cleanly_on_linux(self):
        state, _ = render('php2shell_windows_patch', packages={'php-cli': ['8.3.35']})
        self.assertEqual(list(state), ['php2shell_windows_patch_blocked'])

    def test_windows_scanner_is_wrapped_and_encoded_for_salt(self):
        commands = []
        render('php2shell_identify', family='Windows', scan_commands=commands)
        command, options = commands[0]
        self.assertTrue(command.startswith('& {\n'))
        self.assertTrue(command.endswith('\n}'))
        self.assertTrue(options['encode_cmd'])

    def test_windows_exact_versions_for_php_and_apache(self):
        config = {'windows': {'packages': {'company-php': 'php', 'company-httpd': 'apache'}, 'target_versions': {'company-php': '8.3.36', 'company-httpd': '2.4.69'}, 'services': {'Apache2.4': [r'C:\Apache24\bin\httpd.exe', '-t']}}}
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'company-php': ['8.3.35'], 'company-httpd': ['2.4.68']}, config=config, running=['Apache2.4'])
        installed = args(state['php2shell_windows_fixed_packages'], 'pkg.installed')
        self.assertEqual(installed['pkgs'], [{'company-httpd': '2.4.69'}, {'company-php': '8.3.36'}])
        self.assertTrue(installed['allow_updates'])
        self.assertIn('php2shell_windows_restart_1', state)

    def test_windows_blocks_bad_target_and_missing_worker_strategy(self):
        for config in [{}, {'windows': {'target_versions': {'php': '8.3.35'}}}, {'windows': {'target_versions': {'php': '8.3.36'}}}, {'windows': {'target_versions': {'php': '8.4.27'}, 'no_web_workers': True}}]:
            state, _ = render('php2shell_windows_patch', family='Windows', packages={'php': ['8.3.35']}, config=config)
            self.assertEqual(list(state), ['php2shell_windows_patch_blocked'])

    def test_windows_cli_patch_and_newer_version_no_downgrade(self):
        config = {'windows': {'target_versions': {'php': '8.3.36'}, 'no_web_workers': True}}
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'php': ['8.3.35']}, config=config)
        self.assertIn('pkg.installed', state['php2shell_windows_fixed_packages'])
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'php': ['8.3.37']}, config=config)
        self.assertIn('test.nop', state['php2shell_windows_fixed_packages'])

    def test_windows_iis_restarts_running_pools_only(self):
        config = {'windows': {'target_versions': {'php': '8.3.36'}, 'iis_apppools': ['PHP-Pool', 'Stopped-Pool']}}
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'php': ['8.3.35']}, config=config, pools={'PHP-Pool': {'state': 'Started'}, 'Stopped-Pool': {'state': 'Stopped'}})
        self.assertIn('php2shell_windows_iis_pool_1', state)
        self.assertNotIn('php2shell_windows_iis_pool_2', state)

    def test_windows_mapped_runtime_must_receive_update(self):
        runtime = r'C:\PHP\php-cgi.exe'
        config = {'windows': {'packages': {'company-php': 'php'}, 'target_versions': {'company-php': '8.3.36'}, 'runtime_packages': {runtime: 'company-php'}, 'no_web_workers': True}}
        scan = {'runtimes': [{'path': runtime, 'component': 'php', 'version': '8.3.35'}], 'issues': []}
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'company-php': ['8.3.35']}, config=config, scan=scan)
        self.assertIn('pkg.installed', state['php2shell_windows_fixed_packages'])
        state, _ = render('php2shell_windows_patch', family='Windows', packages={'company-php': ['8.3.36']}, config=config, scan=scan)
        self.assertIn('php2shell_windows_patch_blocked', state)

    def test_windows_scan_powershell_syntax(self):
        import shutil
        import subprocess
        powershell = shutil.which('powershell.exe')
        if not powershell:
            self.skipTest('PowerShell is unavailable on this validation host')
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(STATE_ROOT)))
        script = env.get_template(PREFIX + 'php2shell_windows_scan.ps1.jinja').render(cfg={'windows': {'runtime_paths': [r"C:\PHP's directory\php.exe"]}})
        command = "$scriptText = [Console]::In.ReadToEnd(); $scanTokens = $null; $scanErrors = $null; [void][System.Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$scanTokens, [ref]$scanErrors); if ($scanErrors.Count) { $scanErrors | ForEach-Object { $_.Message }; exit 1 }"
        result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', command], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Also execute the read-only scanner locally to verify its real output
        # shape. It changes neither packages nor service configuration.
        result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', '& {\n' + script + '\n} | ConvertTo-Json -Depth 5'], text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads(result.stdout)
        self.assertIsInstance(inventory['runtimes'], list)
        self.assertIsInstance(inventory['issues'], list)
        self.assertTrue(any('Configured runtime missing:' in issue for issue in inventory['issues']))
        # Exercise the exact command shape that cmd.powershell passes to
        # PowerShell after appending JSON conversion, using Salt's encoding.
        import base64
        commands = []
        render('php2shell_identify', family='Windows', scan_commands=commands)
        salt_command = 'try { ' + commands[0][0] + ' | ConvertTo-Json -Depth 5 } catch { Write-Error $_ }'
        encoded = base64.b64encode(salt_command.encode('utf-16-le')).decode('ascii')
        result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsInstance(json.loads(result.stdout)['runtimes'], list)

        # Discover a module referenced by Apache even without a PHP executable.
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / 'php8apache2_4.dll'
            module.write_bytes(b'')
            config = root / 'httpd.conf'
            config.write_text('Define PHPROOT "' + str(root) + '"\nLoadModule php_module "${PHPROOT}/php8apache2_4.dll"\n', encoding='utf-8')
            script = env.get_template(PREFIX + 'php2shell_windows_scan.ps1.jinja').render(cfg={'windows': {'apache_configs': {str(config): str(root)}}})
            result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', '& {\n' + script + '\n} | ConvertTo-Json -Depth 5'], text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            inventory = json.loads(result.stdout)
            matches = [item for item in inventory['runtimes'] if item['path'].lower() == str(module).lower()]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]['component'], 'php')


if __name__ == "__main__":
    unittest.main()

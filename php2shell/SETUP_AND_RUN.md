# PHP2Shell: Ubuntu lab setup and run guide

This guide uses **Ubuntu 24.04, PHP 8.3, and minion `tt-ubuntu24-1`** to demonstrate:

**Install current repository packages → Needs mitigation → Apply remediation → Mitigated.**

The package baseline covers the original PHP2Shell CVEs. Disabling session upload progress addresses the additional CVE-2026-115560 vector described in the October 23 advisory. This is a configuration-mitigation demonstration, not an exploitation test or proof that an application is exploitable.

## 1. Prerequisites

- A disposable Ubuntu lab VM on an isolated network, with a working Salt minion and permission to install packages and restart services.
- Salt 3006 or newer, with the minion accepted by the master.
- Configured repositories containing the Ubuntu PHP 8.3 security updates.
- Access to the master's state and pillar roots. The paths below use `/srv/salt` and `/srv/pillar` as examples; use your configured roots or equivalent fileserver deployment mechanism.

Run commands below **on the Salt master**:

```bash
salt 'tt-ubuntu24-1' test.ping
salt 'tt-ubuntu24-1' grains.item os osrelease
```

Expect `True`, `Ubuntu`, and `24.04`.

## 2. Deploy the state files

Copy these files from this directory to the state fileserver:

```text
/srv/salt/php2shell/
├── php2shell_identify.sls
├── php2shell_patch.sls
├── php2shell_map.jinja
├── php2shell_upload_progress.jinja
├── php2shell_lab_install.sls
└── files/
    └── php.ini
```

The first four files provide Linux discovery and remediation. The lab state and default INI are needed only for provisioning the demonstration. Imports require the `php2shell/` fileserver location.

For Windows targets, also deploy `php2shell_windows.jinja`, `php2shell_windows_patch.sls`, and `php2shell_windows_scan.ps1.jinja`. Windows additionally requires deployment-specific Winrepo mappings; see [README.rst](README.rst).

Confirm that the master exposes the files:

```bash
salt 'tt-ubuntu24-1' cp.list_master prefix=php2shell/
```

## 3. Configure the Ubuntu demonstration pillar

Create `/srv/pillar/php2shell_demo.sls` with the following data. If you already have PHP2Shell pillar, merge these settings into it instead of creating conflicting definitions.

```yaml
php2shell:
  lab:
    enabled: true
    install_latest: true
    php_branch: '8.3'
    start_services: true
    exercise_mitigation: true

  minimum_versions:
    php8.3-cli: '8.3.6-0ubuntu0.24.04.13'
    php8.3-common: '8.3.6-0ubuntu0.24.04.13'
    php8.3-fpm: '8.3.6-0ubuntu0.24.04.13'
    php8.3-opcache: '8.3.6-0ubuntu0.24.04.13'

  upload_progress:
    ini_files:
      - /etc/php/8.3/fpm/php.ini
    configuration_complete: true
    application_not_affected: false
```

The explicit minima make this lab deterministic even if automatic Ubuntu baseline selection does not match the installed build. Ubuntu identifies this package revision as fixing both original CVEs in [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1). Do not reuse these versions for another distribution or PHP branch.

`install_latest` selects the newest package candidate in the configured repositories for PHP 8.3; it does not add repositories or install an arbitrary upstream release. `exercise_mitigation` deliberately enables upload progress to create the demonstration's starting condition.

Set `configuration_complete: true` only after confirming that this INI covers the lab's web runtime and no other startup INI, FPM pool, or server/directory setting re-enables upload progress. Add any other effective startup INI files to the list. `.user.ini` is not sufficient for this mitigation.

Merge this target into `/srv/pillar/top.sls`, preserving existing entries:

```yaml
base:
  'tt-ubuntu24-1':
    - php2shell_demo
```

Refresh and inspect the actual data received by the minion:

```bash
salt 'tt-ubuntu24-1' saltutil.refresh_pillar
salt 'tt-ubuntu24-1' pillar.get php2shell
```

The `.pillar.example` files in the repository are reference files, not automatically loaded pillar.

## 4. Install the lab packages

```bash
salt 'tt-ubuntu24-1' state.sls php2shell.php2shell_lab_install test=True
salt 'tt-ubuntu24-1' state.sls php2shell.php2shell_lab_install
```

The lab state installs or updates Apache and PHP 8.3 common/CLI/FPM packages, starts the configured services, and sets `session.upload_progress.enabled = 1`. It seeds a missing INI from `salt://php2shell/files/php.ini` while preserving an existing package-provided file.

It does not deploy a PHP application, configure Apache-to-FPM request routing, add an exploit, or open firewall ports. These are unnecessary for demonstrating the state workflow; an actual HTTP application test needs separate application/handler setup.

## 5. Show the initial discovery result

```bash
salt 'tt-ubuntu24-1' state.sls php2shell.php2shell_identify
```

Expected: **NEEDS MITIGATION**, with `Result: False`. Here, false means the assessment found work to do, not that Salt execution failed. The original package fixes should already be present, but upload progress is enabled.

If the result is NEEDS PATCHING or UNDETERMINED, resolve the baseline, package, or configuration-scope issue before presenting the demonstration as ready.

## 6. Apply remediation

```bash
salt 'tt-ubuntu24-1' state.sls php2shell.php2shell_patch test=True
salt 'tt-ubuntu24-1' state.sls php2shell.php2shell_patch
```

Remediation enforces the package minima, applies applicable Apache maintenance, disables upload progress in the declared INI files, checks service configuration, and replaces affected running workers. The INI mitigation triggers the configured restart even when PHP packages need no update.

Check the whole job: failed package or configuration prerequisites block dependent actions. A partial run is not completed remediation.

## 7. Show the mitigated result and validate

```bash
salt 'tt-ubuntu24-1' state.sls php2shell.php2shell_identify
salt 'tt-ubuntu24-1' service.status php8.3-fpm
salt 'tt-ubuntu24-1' file.search /etc/php/8.3/fpm/php.ini 'session[.]upload_progress[.]enabled = 0'
```

Expected: **MITIGATED**, with `Result: True`; the service and file checks should also return true. Confirm the restart completed and perform application health checks where an application is deployed.

MITIGATED means the original package baseline is satisfied and the additional-vector workaround is configured in the confirmed scope. It does not claim a permanent package fix for the additional CVE, prove runtime application behavior, or certify deployments outside discovery coverage.

## 8. Preserve or repeat the demonstration

To leave the VM mitigated, change the existing pillar setting to `exercise_mitigation: false` and refresh pillar. Consider also setting `lab:enabled: false` after provisioning. Do not rerun the reset-enabled lab state after remediation unless you intend to recreate the initial condition.

To repeat intentionally, restore those lab flags to true, refresh pillar, and rerun steps 4–7. Retain job output as evidence of the before/after status, file change, and worker restart.

## Windows lab alternative

Use the same public state names on a dedicated Windows minion. Deploy the shared
states, `files/php.ini`, and these Windows helpers under `/srv/salt/php2shell/`:

- `php2shell_windows.jinja`
- `php2shell_windows_patch.sls`
- `php2shell_windows_scan.ps1.jinja`

Copy [php2shell_lab_windows.pillar.example](php2shell_lab_windows.pillar.example)
to a Windows-specific pillar SLS and target only your Windows lab minion in
`top.sls`. Use it **instead of the Ubuntu lab pillar**. It now matches the supplied
`php83` / `apache24` definitions in [winrepo/](winrepo/README.md). Deploy those
definitions and their wrappers to the master first. For your own installers,
adjust the package names, installation paths, service name, configuration-test
arguments, runtime ownership mappings, and remediation target versions together.

The supplied wrappers provision the Visual C++ runtime, register the dedicated
`SaltPHP2ShellApache` service, and connect PHP to a loopback-only Apache listener
on port 8088. They install into `C:\SaltLabs`, preserving configuration on updates.
Other Winrepo installers must provide the required Visual C++ runtime and compatible
PHP/Apache builds, and register the Apache service if `start_services` is enabled.
Include extra prerequisite packages explicitly in `lab:packages` if they are not
handled by the installers. ZIP archives alone are not installable Winrepo packages.
IIS and its PHP handler/application pools must be provisioned separately if used.

The lab automatically reuses PHP/Apache entries from `windows:packages` and
service names from `windows:services` (plus shared `services`). Explicit
`lab:packages` and `lab:services` override those defaults. The lab also reuses
`windows:target_versions` for selected packages; `lab:package_versions` overrides
individual targets. Any resolved pins select `pkg.installed` for the whole group.
With no version pins or selected Windows targets,
`install_latest: true` selects the latest version available in **your Winrepo**,
using Salt's [package provider](https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.win_pkg.html).
It does not fetch arbitrary releases from the PHP website. Exact
`lab:package_versions` remain available for a package-upgrade demonstration.
Remediation uses the explicit approved `windows:target_versions` independently
of lab overrides.

Run from the Salt master, replacing `win-php-lab` with your minion ID:

```bash
salt 'win-php-lab' saltutil.refresh_pillar
salt 'win-php-lab' pillar.get php2shell
salt 'win-php-lab' pkg.refresh_db
salt 'win-php-lab' pkg.list_available php83 apache24
salt 'win-php-lab' state.sls php2shell.php2shell_lab_install test=True
salt 'win-php-lab' state.sls php2shell.php2shell_lab_install
salt 'win-php-lab' state.sls php2shell.php2shell_identify
salt 'win-php-lab' state.sls php2shell.php2shell_patch test=True
salt 'win-php-lab' state.sls php2shell.php2shell_patch
salt 'win-php-lab' state.sls php2shell.php2shell_identify
```

For the mitigation demo, confirm all effective startup INI files and overrides,
use packages that satisfy the original security baseline, and retain
`exercise_mitigation: true` only while resetting the lab. Expect **NEEDS
MITIGATION → MITIGATED** after a successful repair and worker replacement.
Verify the actual service restart and application health. Set
`exercise_mitigation: false` afterward, as in the Ubuntu workflow.

## Troubleshooting

| Symptom | Action |
|---|---|
| Lab installation disabled or PHP branch missing | Verify `pillar.get php2shell`; `.example` files alone are not loaded. |
| `unique()` rejects `case_sensitive` | Deploy the current `php2shell_upload_progress.jinja`; it uses explicit path deduplication. |
| Unversioned `php-common` reports unknown baseline | Deploy the current map; Debian/Ubuntu packaging utilities are excluded. |
| State requests `>=8.3.36` | Confirm the four explicit Ubuntu minima above reached the minion and the current map is deployed. |
| INI source cannot be found | Deploy `files/php.ini` beneath the fileserver's `php2shell/` directory. |
| INI or restart state has failed requisites | Resolve the first failed package/configuration state, then rerun remediation. |
| Discovery remains UNDETERMINED | Check declared INI paths and coverage; confirm the running deployment uses those files. |
| Result returns to NEEDS MITIGATION | Check whether the lab reset state or another configuration tool re-enabled upload progress. |

For the detailed cross-platform behavior, see [README.rst](README.rst). For a customer walkthrough, open [FOLLOW_THE_MINION.html](FOLLOW_THE_MINION.html).

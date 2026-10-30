# PHP2Shell identification and PHP / Apache patching

## Scope and fixed versions

These states manage existing Linux OS packages on Debian/Ubuntu,
RedHat-family and SUSE minions, and Windows installations through Salt Winrepo,
using Salt 3006 or newer. They do not install a new web stack or change
repository/module-stream configuration. Windows requires deployment-specific
package definitions, exact target versions and service/IIS pool configuration.

Baselines checked on 22 October 2026:

* PHP 8.2: 8.2.35; PHP 8.3: 8.3.36; PHP 8.4: 8.4.27; PHP 8.5: 8.5.12.
  These fix CVE-2026-109618 and CVE-2026-109619 (PHP2Shell).
* Apache HTTP Server: use repository updates by default. No universal upstream
  Apache version is enforced against distribution packages. Set a per-package
  vendor-fixed minimum to enforce a specific Apache advisory. Updating Apache
  alone does not fix PHP2Shell; PHP-FPM and non-Apache deployments also need
  the PHP fix.

Sources:

* https://www.wiz.io/blog/php2shell-php-rce
* https://www.php.net/archive/2026.php
* https://httpd.apache.org/security/vulnerabilities_24.html
* https://docs.saltproject.io/en/latest/ref/states/all/salt.states.pkg.html

## Additional RCE: CVE-2026-115560

The October 23 PHP advisory describes a separate, unusual session-serializer
RCE path. The October 21 fixed versions do not resolve it. No fixed release
is published in that advisory; do not raise package minimums speculatively.
PHP recommends disabling `session.upload_progress.enabled` pending its fix.

Configure `php2shell:upload_progress` (see the pillar example):

* `ini_files`: existing startup PHP INI files for every web runtime, including
  applicable INI overrides. Exclude .user.ini and Apache/FPM pool configuration.
* `configuration_complete: true`: confirm scope and that no other setting
  re-enables upload progress. Static file checks cannot prove runtime behavior.
* Alternatively, `application_not_affected: true` records an application-owner
  review confirming the serializer-switching preconditions do not apply.

Patching also enforces `session.upload_progress.enabled = 0`, saves an INI
backup, and triggers configured worker replacement. Upload-progress indicators
may be affected. Missing scope or restart prerequisites fail the mitigation;
older-CVE package updates can still run, so check the complete job result.
The mitigation follows successful package installation prerequisites.

Discovery now reports NEEDS MITIGATION, MITIGATED, or UNDETERMINED as appropriate.
MITIGATED is not a claim that the additional CVE is patched. Confirm active
workers and rerun application checks. The original package fixes remain required.

References:
https://www.php.net/archive/2026.php and
https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html

The default minimums are derived from each installed PHP branch and package epoch.
They are minimums, not exact version pins: newer packages satisfy them. Future
PHP branches and PHP 8.1 or older need explicit vendor-approved overrides, or
a separate supported-branch migration. These states do not configure module
streams, repositories or package names for a branch migration. Constrain your
repositories/module streams to the intended branch: a minimum constraint on a
generic package name such as `php-fpm` can otherwise select a newer PHP branch.

## Vendor backports

Distribution fixes often retain an older upstream version. Set
`php2shell:minimum_versions` to the full vendor-fixed version for EACH
affected installed package, including epoch and release where applicable.
For example, a vendor-fixed `php-fpm` override does not automatically certify
`php-common` or a second PHP installation. Target pillar by OS release,
repository stream and PHP branch; never reuse a floor from another distribution.
The included `php2shell.pillar.example` shows the shape without inventing
vendor package versions. Overrides take precedence over built-in minimums.

Ubuntu USN-8948-1 backports are recognized automatically when the OS release,
PHP package family and official version pattern match:

* Ubuntu 22.04 / PHP 8.1: 8.1.2-1ubuntu2.28.
* Ubuntu 24.04 / PHP 8.3: 8.3.6-0ubuntu0.24.04.13.
* Ubuntu 26.04 / PHP 8.5: 8.5.4-0ubuntu1.5.
* Ubuntu 26.10 / PHP 8.5: 8.5.9-0ubuntu2.1.

These cover both original PHP2Shell CVEs. Versioned CLI/common/FPM/OPcache
and Apache PHP module packages use the corresponding package-family minimum.
PPA/custom build patterns, other releases and other distributions continue to
use the upstream floors or explicit vendor overrides. Set
`use_vendor_baselines: false` to disable automatic Ubuntu selection.
Version-pattern matching assumes trusted configured repositories; it does not
authenticate a package's provenance independently.

Source: https://ubuntu.com/security/notices/USN-8948-1

For the Ubuntu 24.04 lab, the repository build 8.3.6-0ubuntu0.24.04.13 therefore
meets the original-CVE baseline. Applying the upload-progress workaround and
replacing workers can then produce MITIGATED without requiring PHP 8.3.36.
If package installation fails for another reason, its dependent INI/restart
states still remain blocked; a failed overall job must not be closed as remediated.

For PHP and explicit Apache overrides, the states use the minion's native
`pkg.version_cmp` and `pkg.installed` with `>=` constraints. Repositories
must contain satisfying packages; an older repository candidate causes that
package state to fail. Apache packages without overrides use a separate
`pkg.latest` state; this is repository maintenance, not proof of remediation
for a specific CVE. Package signature checking stays enabled. No repository is
added and no package hold is removed.

For example, Rocky may offer `httpd-2.4.62-13.el9_8.6` while upstream Apache
has a higher version. Do not require `httpd>=2.4.69` just to remediate
PHP2Shell. The exact Rocky release needed for any Apache CVE must be established
from the vendor advisory; the version shown here is not a verified CVE fix.

## Install and run

Keep all `php2shell*.sls` and `php2shell*.jinja` files together, including
`php2shell_windows_scan.ps1.jinja`, under `<file_roots>/php2shell/`.
Map/template imports use the explicit `php2shell/` fileserver path, and
the Windows state include uses `php2shell.php2shell_windows_patch`.
The pillar example belongs in your pillar tree if needed; do not apply it
as an SLS state. Preview on a canary, then roll out in controlled batches:

```console
salt 'web-canary' state.apply php2shell.php2shell_identify
salt 'web-canary' state.apply php2shell.php2shell_patch test=True
salt 'web-canary' state.apply php2shell.php2shell_patch
salt 'web-canary' state.apply php2shell.php2shell_identify
```

Identification is read-only and can be run across a larger inventory:

```console
salt '*' state.apply php2shell.php2shell_identify --out=json
```

## Identification results

Identification returns a single PHP2Shell status with a short comment:

* `NEEDS PATCHING`: PHP packages are below the fixed baseline or require
  vendor-fix verification. Unknown baselines, comparison failures and multiple
  installed versions are conservatively included here. Result is false.
* `ALREADY PATCHED`: installed PHP packages meet the selected fixed baseline.
  Result is true; for the additional RCE, the application owner must also have
  reviewed the vector as not applicable. Confirm the active worker runtime.
* `NEEDS MITIGATION`: original package fixes are present but the declared
  startup INI configuration still enables upload progress. Result is false.
* `MITIGATED`: original package fixes are present and the workaround is
  configured in the confirmed INI scope. Result is true; verify worker replacement.
* `NOT EXPOSED`: no PHP runtime was detected in the platform's inventory scope.
  On Linux this covers OS-managed PHP packages. On Windows it covers registered
  packages plus the runtime locations described below. Result is true; this
  does not certify containers or installations outside that inventory scope.

Unsupported platforms report `UNDETERMINED` with a false result rather than
claiming they are patched or unexposed. Incomplete Windows scans or unknown
binary versions also report `UNDETERMINED`. Apache's independent baseline does not
affect the PHP2Shell status. The patch state still maintains Apache packages.
No JSON inventory or separate Apache assessment is printed.
Missing additional-RCE configuration coverage also reports UNDETERMINED rather
than assuming that meeting the original package minimums is sufficient.

There are no reported changes. Run identification normally rather than with
`test=True`: some Salt versions mask test-state failures in test mode.
Vendor backports can produce conservative `NEEDS PATCHING` findings until
the corresponding vendor-fixed minimums are configured in pillar.

The inventory recognizes common PHP engine/common/CLI/FPM/CGI/OPcache packages,
Debian Apache PHP modules, and common Apache packages. Unversioned Debian PHP
metapackages and the unversioned php-common packaging utilities are skipped in
favor of their versioned runtime dependencies (such as php8.3-common). This
exclusion applies only to Debian/Ubuntu; RPM php-common remains assessed.
Use `extra_php_packages` / `extra_apache_packages` for other package names
and additional extensions, plus vendor minimums when their versions differ.

Containers, Linux source builds, FrankenPHP, LiteSpeed, application
bundles, custom prefixes and unpackaged runtimes need separate inventory and
patching or image rebuild/redeployment. Neither installed-package inventory
nor the CLI version proves which runtime a web request uses. Check application
deployment configuration and use your vulnerability scanner after the rollout.

## Windows identification and patching

The same public state names automatically select Windows or Linux:

* `php2shell.php2shell_identify` returns the short PHP2Shell status.
* `php2shell.php2shell_patch` includes `php2shell_windows_patch.sls`
  on Windows and uses the existing Linux path elsewhere.

Windows discovery reads installed software via `pkg.list_pkgs`. It also runs
a read-only PowerShell scan of PATH, common C:\PHP/Apache/XAMPP/WAMP locations,
running PHP/Apache processes, service executable paths and IIS FastCGI/handler
paths in `applicationHost.config`. Binary versions are read from file metadata;
the scanner does not execute discovered programs. Add every custom executable
or PHP DLL path under `php2shell:windows:runtime_paths`, especially paths on
other drives. This is a bounded scan, not a recursive disk inventory. Access
errors or missing configured runtime files prevent an unexposed verdict.

Identification needs no Winrepo package mapping for portable binaries: it can
compare their versions directly against the PHP branch baseline. Patching
requires every discovered binary to have an explicit `runtime_packages`
entry whose owner is installed and has a matching role under `packages`.
Runtime-path mappings ignore letter case, consistent with Windows paths.
INI path deduplication also ignores Windows letter case while preserving distinct
Linux paths; it does not depend on Jinja-specific `unique` filter arguments.
This prevents updating one registered installation while leaving another
portable copy behind. Fixed but unmapped binaries can be identified as already
patched, but patch execution still requires their deployment mapping.

Prepare Windows-targeted pillar using `php2shell.pillar.example`:

1. Create/maintain approved Winrepo definitions for your PHP and Apache
   installations. Configure the actual package names under `windows:packages`.
2. Put approved exact versions under `windows:target_versions`. These versions
   must exist in the minion's Winrepo metadata. `>=` constraints and `latest`
   are not used on Windows. PHP targets must meet the same fixed branch minimums;
   implicit branch migrations and downgrades are rejected/skipped.
3. Map all discovered executable paths under `windows:runtime_packages`.
   A wrapper for a ZIP deployment must register a consistent package identity
   so Salt can track its installed version. XAMPP/WAMP bundles need their own
   deployment definition; do not treat the bundle version as the PHP version.
4. Configure actual Apache Windows services and config-test argv lists under
   `windows:services` and/or IIS pool names under `windows:iis_apppools`.
   The state verifies the configured service/pool exists. Only running services
   and started pools are restarted. CLI-only deployments may explicitly use
   `windows:no_web_workers: true`.

Use approved installer/wrapper definitions that verify their payloads, preserve
php.ini, Apache configuration, certificates and compatible extensions, and
stop relevant workers while replacing locked binaries. This state does not
perform an arbitrary in-place ZIP overwrite or synthesize missing Winrepo
definitions. Windows package dependencies (VC runtime, extension ABI, TS/NTS
and x86/x64 compatibility) belong in those deployment definitions. Salt Winrepo
does not resolve dependencies automatically.

Refresh the approved Windows package metadata before the canary rollout:

```console
salt 'windows-canary' pkg.refresh_db
salt 'windows-canary' state.sls php2shell.php2shell_identify
salt 'windows-canary' state.sls php2shell.php2shell_patch test=True
salt 'windows-canary' state.sls php2shell.php2shell_patch
salt 'windows-canary' state.sls php2shell.php2shell_identify
```

Recheck application health and verify that every worker uses the updated
runtime. IIS pool recycling may drain old workers asynchronously; wait for old
workers to exit. An interrupted rollout can be retried with `force_restart`.
Windows identification can cause Salt to populate its Winrepo metadata cache;
it does not install packages or change service configuration.

References:

* https://docs.saltproject.io/en/latest/topics/windows/windows-package-manager.html
* https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.win_pkg.html

## Apache and PHP2Shell

PHP2Shell applies to Apache when it hosts affected PHP through mod_php or
forwards requests to affected PHP FastCGI/FPM workers. Apache without PHP is
not affected by these PHP CVEs. The remediation is to update the PHP engine
and replace the workers using it; there is no Apache HTTP Server version
whose installation alone fixes PHP2Shell. The existing Apache package updates
in this workflow are separate maintenance, not the PHP2Shell security gate.

On Linux, the inventory includes Debian libapache2-mod-php packages, SUSE
apache2-mod_php packages and RPM mod_php/php packages. The patch state upgrades
those PHP modules to their branch minimum (or a vendor backport override),
checks Apache configuration, and restarts running Apache when PHP changes.
With FPM, the FPM workers are also restarted. Configure custom service units
and runtime packages explicitly when the normal names do not apply.

On Windows, the scanner recognizes php8apache2_4.dll (and older PHP-major
equivalents) in explicit runtime paths and in PHP LoadModule directives from
Apache conf files. It reads *.conf beneath the conf directory of discovered
Apache roots; add custom files and their ServerRoot under windows:apache_configs.
It resolves SRVROOT and simple Define values within each file. Conditional
sections are treated conservatively; cross-file variables or includes outside
these locations require explicit runtime_paths. Unresolved or missing referenced
PHP modules report an incomplete assessment rather than NOT EXPOSED.

Map the PHP module DLL to its PHP Winrepo package, not the Apache package, and
configure the actual Apache Windows service plus its httpd.exe -t config test.
The Windows patch state refuses to treat an IIS pool restart or a CLI-only
declaration as sufficient for a detected Apache PHP module. Updating the PHP
package triggers the configured Apache service restart even if Apache's own
package version does not change.

## Restarts and operational checks

Packages with explicit minimums are submitted together to the package manager
so it can resolve matching dependencies. Apache repository-only updates use
a separate transaction and cannot block PHP package installation or FPM
restarts. A PHP package failure can still block an Apache restart because
Apache may host mod_php. Automatic service handling covers Apache and
FPM units inferred from package names; add custom units and config-test argv
lists under `php2shell:services`. Alternate-prefix FPM installations generally
need an explicit config-test path (see the pillar example).

For units running when the SLS is rendered, configuration is tested after
package installation. A failing test prevents that unit's Salt restart.
Tests invoke the `cmd.run_all` execution module through `module.run`, with
an argv list and `python_shell: false`. `module.run` checks the returned
`retcode`; a nonzero exit status fails the state and blocks the restart.
Do not put `python_shell` directly on a `cmd.run` state: Salt versions
that pass it internally can raise a duplicate-keyword error.
Services watch the package state and restart when packages change; this is a
restart rather than a graceful reload so old workers can be replaced. Stopped
units are not started by these states, and boot enablement is not changed.
Package-manager maintainer scripts may independently restart or start services
before Salt's configuration checks run. Use a maintenance window and perform
application health checks; no load-balancer draining is included.

After an interrupted rollout or a failed restart, force another restart even
if the package versions already satisfy the baseline:

```console
salt 'web-canary' state.apply php2shell.php2shell_patch pillar='{"php2shell":{"force_restart":true}}'
```

Preserve any vendor overrides in normal targeted pillar when using this
command. Confirm every web-serving worker has been replaced, including custom
CGI supervisors, before closing the finding. Perform an application-level
health check as well as the service status checks included here.

## Optional live lab installation

`php2shell.php2shell_lab_install` installs a test stack; it is never included
by discovery or remediation. Use a disposable VM on an isolated lab network.
The opt-in pillar example is `php2shell_lab.pillar.example`. The state uses
the platform's Apache, PHP CLI/common and PHP-FPM packages. The active example
selects Ubuntu PHP 8.3 and its FPM INI path; change the path to /etc/php.ini
for a normal Rocky/RHEL deployment. Debian/Ubuntu requires an explicit available
PHP branch. SUSE package/service names can be overridden.
Windows needs actual Winrepo definitions. Use
`php2shell_lab_windows.pillar.example` instead of the Ubuntu example.
Separate lab definitions for `php83` and `apache24`, installer wrappers and
deployment instructions are supplied in `winrepo/README.md`. The example now
matches those packages, their `C:\SaltLabs` paths and `SaltPHP2ShellApache`
service. Deploy the definition/wrapper files before refreshing Windows metadata.
The lab defaults to PHP/Apache names in `windows:packages` and service names
in `windows:services` (including shared `services`); explicit `lab:packages`
and `lab:services` take precedence. Installers must supply runtime dependencies
and register the configured Apache service. IIS provisioning remains separate.

Windows lab installation also reuses `windows:target_versions` for selected
packages, with individual `lab:package_versions` taking precedence. Any
resolved pins select `pkg.installed` for the entire package group.

Without resolved pins, Linux and Windows default to `pkg.latest`: the latest package candidate available in the
configured repository and selected branch/stream, including updates to existing
installations. This is not necessarily the newest upstream PHP release. Set
`lab:install_latest: false` for install-only behavior. Supplying any exact
`lab:package_versions` selects `pkg.installed` for the entire package group;
the specified versions are enforced and unpinned packages are only ensured
present. Windows pins, when supplied, must be exact numeric Winrepo versions.
Windows remediation still uses explicit `windows:target_versions`; the lab's
latest selection does not change remediation targets or security baselines.

An affected PHP engine must serve web requests for remote exposure. Apache
alone, or a CLI-only PHP installation, does not establish this web RCE exposure.
The additional CVE also requires upload progress enabled and the specific
session-serializer configuration/runtime switch described in the PHP advisory.
Installing packages or seeing NEEDS MITIGATION does not prove exploitability.

The lab state installs packages and can start their services. It does not wire
Apache to FPM, deploy a PHP application, open firewall ports, add repositories
or implement an exploit. For an actual HTTP test, configure a benign application
and its PHP handler separately. State discovery/patch tests can use the installed
package inventory without an HTTP endpoint.

Merge the adjusted lab pillar example onto a dedicated minion and run:

```console
salt 'php-lab' state.sls php2shell.php2shell_lab_install test=True
salt 'php-lab' state.sls php2shell.php2shell_lab_install
salt 'php-lab' state.sls php2shell.php2shell_identify
salt 'php-lab' state.sls php2shell.php2shell_patch test=True
salt 'php-lab' state.sls php2shell.php2shell_patch
salt 'php-lab' state.sls php2shell.php2shell_identify
```

The normal repository candidate may already contain the older-CVE fixes.
For a mitigation demonstration, use those fixed packages with the example's
`exercise_mitigation: true` and confirmed INI scope. Discovery should report
NEEDS MITIGATION after lab setup, then MITIGATED after remediation and worker
replacement. A stale repository or vendor backport may still require package
updates or verified minimum-version overrides before this outcome is possible.
To test NEEDS PATCHING, stage appropriate earlier and fixed vendor builds in
your lab repository and set exact full `lab:package_versions` for a supported
PHP branch. Backported fixes must be evaluated against vendor advisories.
Exact versions can downgrade installed packages, so use a fresh VM or snapshot.
Older/EOL default streams can legitimately cause remediation to block; select
a supported stream before provisioning if testing a complete patch rollout.

To test NEEDS MITIGATION -> MITIGATED with current PHP packages, explicitly set
`lab:exercise_mitigation: true`. This resets upload progress to enabled in the
declared startup INI files; normal remediation disables it again. Missing INI
files are seeded with `file.managed` from `salt://php2shell/files/php.ini`
before `file.replace` applies the lab setting. Existing package-provided
INI files are preserved. Deploy the `files/` directory alongside the states.
The supplied minimal INI is for lab use; extension settings are deployment-specific.
Configure
INI scope and actual service/config tests in the regular remediation pillar.
This exercise does not add the serializer-switching application code required
for the additional RCE. Disable the lab reset flag before scheduling normal
remediation, or a later lab-state run would re-enable upload progress.

## Maintenance and compatibility

Linux and Windows share one service-handling template in php2shell_map.jinja.
The public state names, php2shell/ fileserver paths, existing state IDs and
pillar settings remain compatible. Deploy all state/template files together
when updating; the patch states now depend on the shared template macro.

Discovery uses explicit assessment flags rather than diagnostic message text.
Empty package-version lists require review. Malformed Windows scan results
produce UNDETERMINED instead of a render error or an unexposed verdict. The
Windows scanner runs in an encoded PowerShell script block compatible with
Salt's appended JSON conversion. Config-test commands must be nonempty argv
lists; dictionaries and shell strings are rejected. Calling the Windows-only
patch state on Linux fails with a platform message; the public patch state
continues to select the correct platform automatically.

## Offline validation

With Jinja2 and PyYAML available, run:

```console
python secops/vulnerability/php2shell/test_php2shell_render.py -v
```

These checks render both SLS files with mocked Salt functions and parse the
result as YAML. They cover branch baselines, vendor overrides, epochs,
unsupported/EOL branches, multiple installed versions, service handling and
custom configuration. A regression check also exercises Salt's command-result
interpretation using the Salt source included in this repository.
Windows checks cover platform dispatch, exact targets, registered and portable
PHP detection, missing scan data, Apache targets, package ownership, no-downgrade
behavior, IIS pool handling and worker strategy requirements. When PowerShell
is available, its native parser checks the rendered discovery script and the
read-only scanner executes locally to validate its output shape.
Regression checks also validate all rendered state requisites, preserved service
state IDs, case-insensitive Windows mappings, empty version lists and malformed
scan data. The encoded scanner is exercised with Salt's JSON command shape.
They do not exercise a native package manager, live
Salt minion, application health or package maintainer scripts.

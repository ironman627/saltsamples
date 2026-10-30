# PHP2Shell v3: production setup and operation

This package identifies PHP runtimes requiring review, updates existing managed
PHP/Apache packages, disables PHP session upload progress where configured, and
replaces running web workers. It supports Salt 3006+ on Debian/Ubuntu,
RedHat-family and SUSE Linux, and Windows with PowerShell 5.1+ and Salt Winrepo.
Use existing Salt master/minion connectivity and administrator/root privileges.

## Package contents

| Path in ZIP | Purpose |
| --- | --- |
| `README.md` | This production runbook |
| `php2shell/*.sls`, `php2shell/*.jinja` | Seven required assessment, remediation and inventory files; deploy together |
| `pillar/php2shell.pillar.example` | Commented cross-platform configuration reference; copy and customize in the pillar tree |
| `windows-winrepo/` | Corrected ZIP installer and matching definitions for existing wrapper-owned installations only; see its README |
| `SHA256SUMS` | Integrity hashes of every other file in the ZIP |

Lab provisioning/reset states, seed INI files, lab pillars, presentations, tests,
older archives, credentials and environment inventory are excluded. The core
states need no custom Salt modules or Python libraries beyond Salt itself.
Windows installer payloads and Linux packages are obtained from approved sources;
the ZIP contains no PHP/Apache binaries.

## 1. Establish the remediation scope

Inventory every web application, PHP branch, package source, effective startup
INI, service, IIS pool and custom runtime path. Take application/configuration
backups and retain approved previous packages or a VM/image recovery point.
Schedule worker replacement, drain traffic where required, and select a canary
for each OS/repository/PHP/handler combination. These states do not drain traffic.

The packaged upstream minimums are PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 for
CVE-2026-109618 and CVE-2026-109619. Matching official Ubuntu release/build
families use USN-8948-1 backport minimums. For other vendor backports, configure
the full vendor-approved version for EACH installed runtime package, including
epoch/release. EOL or unknown branches require an approved override or a separate
migration. Keep repositories/module streams on the intended PHP branch: Linux
minimum constraints do not themselves prevent a repository from changing it.

As checked on 2026-10-29, PHP's October 23 advisory recommends disabling
`session.upload_progress.enabled` pending a release for the additional
CVE-2026-115560 vector. The original package floors alone do not resolve that
vector. Review current vendor advisories before each rollout; this is a versioned
snapshot, not an automatically maintained vulnerability feed.

Apache without PHP is not affected by these PHP issues. Apache maintenance is
separate: Linux Apache packages without explicit minima use repository updates;
Windows Apache updates use configured exact targets. Neither proves a particular
Apache CVE is fixed. Review that vendor's advisory if such assurance is required.

Sources: [PHP advisories and Windows rebuilds](https://www.php.net/archive/2026.php),
[Ubuntu backports](https://ubuntu.com/security/notices/USN-8948-1),
[Salt package states](https://docs.saltproject.io/en/latest/ref/states/all/salt.states.pkg.html),
[Salt Winrepo](https://docs.saltproject.io/en/latest/topics/windows/windows-package-manager.html).

## 2. Deploy the seven runtime files

Extract the ZIP to a staging directory on the Salt master. Assuming the default
`/srv/salt` base fileserver root, copy the supplied `php2shell/` directory to
`/srv/salt/php2shell/`. Back up an existing directory before updating. Keep all
seven files at that exact relative path: imports use `php2shell/`. For another
environment, place the directory in its configured file root and pass
`saltenv=ENVIRONMENT` consistently in Salt commands. Configure pillar in the
matching pillar environment as needed.

Do not copy the whole ZIP into the state tree or replace an existing `top.sls`.
The following commands run on the Salt master; replace the example minion IDs.

## 3. Configure targeted pillar

Copy `pillar/php2shell.pillar.example` into your pillar tree as a real `.sls`
file and customize it. Merge separate Linux and Windows targets into your
existing pillar top file, for example:

```yaml
base:
  'linux-web-canary':
    - php2shell_linux
  'windows-web-canary':
    - php2shell_windows
```

Never apply the pillar example as a state. Set `configuration_complete: true`
only after establishing that every effective web-runtime startup INI and
enabling override is covered. Include applicable `conf.d` startup INI files.
Do not use `.user.ini`, Apache config files or FPM pool config as INI targets.
Resolve enabling pool/server/directory overrides separately. The flag records
operator review; the state cannot prove effective configuration coverage.

Alternatively, `application_not_affected: true` records an application-owner
review that the advisory's serializer-switching preconditions do not apply;
it skips this workaround, not the original package fixes.

### Linux example: Ubuntu 24.04 PHP 8.3 FPM

`/srv/pillar/php2shell_linux.sls`:

```yaml
php2shell:
  use_vendor_baselines: true
  upload_progress:
    ini_files:
      - /etc/php/8.3/fpm/php.ini
    configuration_complete: true
    application_not_affected: false
  services:
    php8.3-fpm: ['/usr/sbin/php-fpm8.3', '-t']
```

Adapt the INI and executable paths to the application. For Apache mod_php,
include its effective INI, such as `/etc/php/8.3/apache2/php.ini`. Common Apache
and FPM services are inferred; `services` adds or overrides configuration tests
for custom units. Supply tests as nonempty argv lists. Other distributions or
vendor streams may need `minimum_versions` for all affected packages. Use
`extra_php_packages` for unrecognized runtime package names and extensions;
independently versioned extensions need their own verified minimums. Optional
`fromrepo` selects an already configured repository through the native provider.
No repository, hold, module stream or branch migration is managed here.

### Windows example: an existing company-managed Apache/PHP installation

`/srv/pillar/php2shell_windows.sls` (replace names, paths and targets):

```yaml
php2shell:
  upload_progress:
    ini_files: ['D:\Apps\PHP83\php.ini']
    configuration_complete: true
    application_not_affected: false
  windows:
    packages:
      company-php83: php
      company-apache24: apache
    target_versions:
      company-php83: '8.3.36.1'
      company-apache24: '2.4.69'
    runtime_paths:
      - 'D:\Apps\PHP83\php.exe'
      - 'D:\Apps\PHP83\php-cgi.exe'
      - 'D:\Apps\PHP83\php8apache2_4.dll'
      - 'D:\Apps\Apache24\bin\httpd.exe'
    runtime_packages:
      'D:\Apps\PHP83\php.exe': company-php83
      'D:\Apps\PHP83\php-cgi.exe': company-php83
      'D:\Apps\PHP83\php8apache2_4.dll': company-php83
      'D:\Apps\Apache24\bin\httpd.exe': company-apache24
    services:
      Apache2.4: ['D:\Apps\Apache24\bin\httpd.exe', '-t']
```

These `company-*` names are placeholders for YOUR approved Winrepo definitions,
not packages provided by this ZIP. Targets must exist in Winrepo and match its
installed-software identities. A fourth version component may represent a
Windows dependency rebuild; the PHP engine still reports three components.
Use exact numeric versions, never `latest` or Linux `>=` syntax. PHP targets
must meet the branch floor; branch migration is a separate deployment.

Keep only actual existing runtime paths; a missing explicit path makes the
assessment incomplete. Map EVERY discovered executable/PHP module to an installed
package and its component role. Add nondefault Apache config paths with
`windows:apache_configs` as shown in the pillar reference. Windows discovery
also checks common locations, processes, service paths and IIS configuration.

For IIS/FastCGI, use actual `windows:iis_apppools` and configure Salt's `win_iis`
prerequisites; omit the Apache settings if absent. Recycling requires running
pools and waiting for old workers to drain. For mod_php, an Apache service and
its configuration test are required; IIS recycling does not replace those
workers. `windows:no_web_workers: true` applies only to reviewed CLI-only systems.

Your installers must handle locked binaries, VC runtime and extension ABI/TS/NTS
compatibility, verify payloads, preserve configuration/content/certificates, and
register stable installed-package identities. Winrepo does not resolve these
dependencies automatically. See `windows-winrepo/README.md` if you already use
the fixed-path `php83`/`apache24` wrappers included here.

## 4. Identify and preview on canaries

```bash
salt 'linux-web-canary' saltutil.refresh_pillar
salt 'windows-web-canary' saltutil.refresh_pillar
salt 'windows-web-canary' pkg.refresh_db
salt 'windows-web-canary' pkg.list_available company-php83 company-apache24
salt 'linux-web-canary' state.sls php2shell.php2shell_identify
salt 'windows-web-canary' state.sls php2shell.php2shell_identify
salt 'linux-web-canary' state.sls php2shell.php2shell_patch test=True
salt 'windows-web-canary' state.sls php2shell.php2shell_patch test=True
```

Inspect the actual package candidates, pillar and rendered changes. Run
identification normally: test mode can mask negative assessment results on some
Salt versions. Discovery does not install packages or change services; Windows
may populate Winrepo metadata caches. Preview evaluates inventory and does not
prove that downloads/installers or later configuration tests will succeed.

| Assessment | Meaning/action |
| --- | --- |
| NEEDS PATCHING | PHP is below baseline, has an unknown fix baseline, or needs version/vendor review |
| NEEDS MITIGATION | Package floors are met but declared INI scope needs the workaround |
| MITIGATED | Floors and confirmed static workaround scope are satisfied; verify active workers |
| ALREADY PATCHED | Floors met and additional vector reviewed as not applicable; verify active workers |
| NOT EXPOSED | No PHP found within this scanner's scope; review other deployments separately |
| UNDETERMINED | Unsupported platform, incomplete scan, or missing configuration coverage |

A false assessment result can represent a finding; inspect the comment. A true
assessment is conditional on scope, trusted package sources and vendor minima.
Linux discovery covers OS packages, not arbitrary source builds, containers or
bundled runtimes. Windows scans bounded locations, not every disk recursively.
Use separate image rebuilds/package workflows for out-of-scope deployments.

## 5. Apply, verify and expand

```bash
salt 'linux-web-canary' state.sls php2shell.php2shell_patch
salt 'windows-web-canary' state.sls php2shell.php2shell_patch
salt 'linux-web-canary' state.sls php2shell.php2shell_identify
salt 'windows-web-canary' state.sls php2shell.php2shell_identify
```

Review the COMPLETE job: a package, config-test, mitigation or restart failure
means remediation remains incomplete. Only services running at render time and
started IIS pools are replaced. Stopped services stay stopped; boot enablement
is unchanged by the patch states. Package installers may independently start or
restart services before Salt's checks. Linux PHP and Apache maintenance use
separate transactions; successful PHP updates do not imply Apache success.

Verify application HTTP health, restart/worker timestamps, loaded runtime
versions and effective `session.upload_progress.enabled=0` in the actual web
SAPI. CLI `php --ini`/`php -v` alone do not prove web-worker configuration.
Use an existing authenticated diagnostic or a temporary local probe that you
remove immediately; do not publish `phpinfo()`. Re-run your vulnerability scan.
Repeat the patch state and confirm no unexpected changes before expanding.

Roll out to an explicitly reviewed target list in small batches:

```bash
salt -L 'web01,web02,web03' -b 1 state.sls php2shell.php2shell_patch
salt -L 'web01,web02,web03' state.sls php2shell.php2shell_identify --out=json
```

Batching limits concurrency; review results between rollout groups. Retain job
IDs/output, approved versions, before/after health and worker evidence.

## 6. Troubleshooting and recovery

| Symptom | Resolution |
| --- | --- |
| Configured Windows service does not exist | Confirm `service.get_all`, `pkg.version`, executable paths and installer logs. Repair a missing installation/service or correct the pillar name. Patch states deliberately do not provision absent services. |
| `php83` installed but `apache24`/`SaltPHP2ShellApache` absent | For existing wrapper deployments, deploy the corrected matching Winrepo assets and refresh metadata; inspect installation errors before retrying the exact approved package. The wrapper's prior PowerShell downloader could receive an HTTP 308 response. |
| Unknown baseline / candidate below minimum | Confirm vendor advisory, full epoch/release, repository stream and per-package overrides. Do not lower the security floor merely to make the state pass. |
| Missing Winrepo target or runtime owner | Deploy approved definitions, refresh metadata, check installed identity and complete `packages`/`runtime_packages` mappings. |
| INI coverage UNDETERMINED | Review effective startup INIs and overriding settings; correct paths and the coverage assertion. |
| Config test or restart fails | Restore valid configuration, resolve the first failed requisite, then retry. Do not close the finding while old workers remain. |
| MITIGATED but workload still uses old settings | Check actual web SAPI, alternate INIs and worker replacement; inspect custom supervisors and IIS draining. |

For an interrupted rollout, after fixing the cause, force replacement of
currently running workers even if packages/settings already meet the baseline:

```bash
salt 'web-canary' state.sls php2shell.php2shell_patch pillar='{"php2shell":{"force_restart":true}}'
```

Keep normal vendor overrides and configuration in targeted persistent pillar.
INI edits retain `.php2shell.bak` backups, but later runs may update backups;
retain independent backups before rollout. Recovery is operator-controlled:
restore approved configuration and compatible packages/images from your change
plan, then validate health and reassess exposure. The states do not implement
automatic package downgrades or vulnerability-safe rollback. Re-enabling upload
progress restores exposure unless the application is independently verified
unaffected or an approved permanent fix has been deployed.

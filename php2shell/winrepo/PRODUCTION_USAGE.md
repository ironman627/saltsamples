# Windows Winrepo assets supplied with PHP2Shell v3

These files preserve support for EXISTING installations created by the included
fixed-path wrappers. They are optional for the generic remediation states.
They are not a general installer for arbitrary production PHP/Apache layouts.

| Package | Exact Winrepo version | Owned path |
| --- | --- | --- |
| `php83` | `8.3.36.1` (engine 8.3.36) | `C:\SaltLabs\PHP83` |
| `apache24` | `2.4.69` | `C:\SaltLabs\Apache24` |

The wrappers require x64 Windows, administrator/SYSTEM rights, PowerShell 5.1+
and outbound HTTPS to the pinned software sources and Microsoft VC runtime
download endpoints. Archive hashes and the VC runtime's Microsoft signature
are verified. The corrected downloader streams .NET HTTP responses, follows
at most ten redirects and rejects non-HTTPS destinations. Installer failures
include the PowerShell script stack for diagnosis.

The installer refuses to modify pre-existing directories without matching
ownership markers. Updates preserve `php.ini`, Apache `conf`, `htdocs` and logs;
an existing running `SaltPHP2ShellApache` is stopped while files are replaced
and restarted afterward. It is configured for PHP x64 TS/mod_php. New Apache
provisioning binds to loopback `127.0.0.1:8088` and leaves the new service stopped.
Removal deletes owned directories including configuration/content: do not use
package removal as a rollback procedure.

For unrelated production installations, maintain organization-approved Winrepo
definitions and installers appropriate to the actual layout. Use the main
runbook's `company-*` example. Do not rename/map an unrelated installed product
to `php83`/`apache24` simply to satisfy ownership checks. No lab provisioning or
reset state is included in v3.

## Deploy definitions for existing wrapper installations

The supplied SLS installer URLs assume a fileserver rooted at `/srv/salt` and
these locations:

```text
/srv/salt/win/repo-ng/salt-winrepo-ng/_/php83.sls
/srv/salt/win/repo-ng/salt-winrepo-ng/_/apache24.sls
/srv/salt/win/repo-ng/salt-winrepo-ng/_/php2shell_install/install.cmd
/srv/salt/win/repo-ng/salt-winrepo-ng/_/php2shell_install/install.ps1
```

Back up current assets, then copy the two SLS files and `php2shell_install/` to
that destination. Check for duplicate `php83`/`apache24` definitions elsewhere
in the Winrepo tree and reconcile them first; each package must have a single
authoritative definition. These are fileserver artifacts, not states to apply.
For durable operation, version them in your custom Winrepo source. If you move
the installer directory, update BOTH `installer` URLs together and preserve
`cache_dir: true` so both wrapper files reach the minion. A managed checkout
refresh may discard uncommitted local assets.

```bash
salt 'windows-canary' pkg.refresh_db
salt 'windows-canary' pkg.list_available php83 apache24
salt 'windows-canary' pkg.get_package_info apache24
salt 'windows-canary' pkg.version php83 apache24
salt 'windows-canary' service.available SaltPHP2ShellApache
```

Metadata refresh must report no failed definitions. Configure your normal
Windows pillar with the package versions above, service
`SaltPHP2ShellApache: ['C:\SaltLabs\Apache24\bin\httpd.exe', '-t']`, effective
`C:\SaltLabs\PHP83\php.ini`, and runtime ownership mappings for `php.exe`,
`php-cgi.exe`, `php8apache2_4.dll` and Apache `bin\httpd.exe` in their owned trees.
Use the main runbook for coverage review, preview, patching and health checks.

If an approved previous provisioning attempt left Apache absent, repair it
separately before running remediation:

```bash
salt 'windows-canary' pkg.install apache24 version=2.4.69 refresh=True
salt 'windows-canary' cmd.run_all 'C:\SaltLabs\Apache24\bin\httpd.exe -t'
```

Review the complete result, paths and configuration before starting any newly
registered service according to the application's operating plan. The generic
patch state preserves stopped services; it will not start that service for you.
Do not reinstall already healthy packages solely to test the wrapper.

These definitions are pinned, not a release feed. Future approved releases need
new verified source URLs, SHA256 values, installed versions and matching targets.
For offline environments, stage signed/hash-verified payloads using your approved
installer process; the included wrapper expects its configured HTTPS sources.

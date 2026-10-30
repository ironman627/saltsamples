# Windows PHP2Shell lab packages

Separate Winrepo definitions provide **php83** and **apache24**. These are
dedicated lab packages, with a shared silent installer for the upstream ZIPs.
They do not adopt or overwrite unrelated PHP or Apache installations.

| Package | Winrepo version | Install directory |
|---|---|---|
| `php83` | `8.3.36.1` | `C:\SaltLabs\PHP83` |
| `apache24` | `2.4.69` | `C:\SaltLabs\Apache24` |

PHP is the x64 Thread Safe build `8.3.36-1`; its engine reports `8.3.36`.
The numeric fourth component records the Windows dependency rebuild for
Winrepo and is compatible with the remediation state's numeric version checks.
Sources and pinned SHA256 values come from the
[PHP Windows downloads](https://www.php.net/downloads.php?os=windows&version=8.3)
and [Apache Lounge downloads](https://www.apachelounge.com/download/).
These definitions offer the listed versions, not an automatically updated
upstream release feed. Add new verified definitions when versions change.

## Deploy to salt-raas.sandbox.set.lab

Copy this directory to a temporary location on the master, then run its
`deploy-winrepo.sh` with Bash. It backs up conflicting files and places:

```text
/srv/salt/win/repo-ng/salt-winrepo-ng/_/
├── php83.sls
├── apache24.sls
└── php2shell_install/
    ├── install.cmd
    └── install.ps1
```

The wrappers are required: the upstream ZIPs are not silent EXE/MSI installers.
The SLS definitions use `cache_dir: true` to distribute both wrapper files.

```bash
bash /path/to/copied/winrepo/deploy-winrepo.sh
salt 'salt-win01-rr' pkg.refresh_db
salt 'salt-win01-rr' pkg.list_available php83 apache24
```

Confirm metadata refresh has zero failed definitions and both versions appear.
No package installation occurs during these commands. The fileserver must
expose `/srv/salt` as used by the `salt://win/repo-ng/...` installer URLs.

The requested destination is inside a managed Git checkout. Keep this source
copy: a later `winrepo.update_git_repos` may overwrite/remove local additions.
For ongoing use, maintain a separate custom Winrepo directory/repository and
adjust the installer URLs accordingly. See Salt's
[custom definition guidance](https://docs.saltproject.io/en/latest/topics/windows/windows-package-manager.html#maintaining-package-definition-files).

## Use with the lab state

Load `../php2shell_lab_windows.pillar.example` as an actual pillar SLS for
`salt-win01-rr`, instead of the Ubuntu lab pillar. It contains matching package
names, INI paths, runtime ownership mappings, service name and patch targets.
Refresh pillar and preview:

```bash
salt 'salt-win01-rr' saltutil.refresh_pillar
salt 'salt-win01-rr' pillar.get php2shell
salt 'salt-win01-rr' state.sls php2shell.php2shell_lab_install test=True
```

When ready, install the lab, identify, patch, and identify again using the
commands in `../SETUP_AND_RUN.md`. The expected current-build demonstration
is NEEDS MITIGATION → MITIGATED. No vulnerable older build is included.

## Installer behavior

- Requires x64 Windows with PowerShell 5.1+, administrator/SYSTEM rights and
  outbound HTTPS to the software sources and Microsoft's VC runtime endpoint.
- Verifies each ZIP's pinned SHA256 before extraction. Installs Microsoft's
  x64 VC redistributable only after a valid Microsoft Authenticode signature.
- Registers stable Windows uninstall entries so `pkg.list_pkgs` can detect
  the package name and version. Retains wrappers in `C:\ProgramData\SaltPHP2Shell`.
- Registers `SaltPHP2ShellApache`; leaves a new service stopped for the lab
  state to start. An already running lab service is stopped during binary
  replacement and started again afterward.
- Binds a fresh Apache installation to **127.0.0.1:8088** and wires the lab PHP
  module once both packages exist, regardless of installation order. Adds no
  firewall rules, remotely reachable listener or exploit/application code.
- Preserves existing lab `php.ini`, Apache configuration, web content and logs
  during upgrades, and runs `httpd.exe -t` before registering success.
- `pkg.remove php83` / `pkg.remove apache24` remove only wrapper-owned fixed
  lab directories and package registry entries, including their lab data.
  PHP removal disables the lab PHP include; Apache removal unregisters its service.

The wrappers require a Windows canary installation to validate package and
runtime behavior in the target environment. Parsing/render checks do not
establish a successful live installation.

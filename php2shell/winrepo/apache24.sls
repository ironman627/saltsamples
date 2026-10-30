# Apache Lounge x64 VS18 build for the isolated PHP2Shell lab.
# Source: https://www.apachelounge.com/download/
# Checksum: https://www.apachelounge.com/download/VS18/binaries/httpd-2.4.69-261002-Win64-VS18.zip.txt
{% if grains.get('cpuarch', '') | lower in ['amd64', 'x86_64'] %}
apache24:
  '2.4.69':
    full_name: 'Apache HTTP Server 2.4 (Salt Lab x64)'
    installer: 'salt://win/repo-ng/salt-winrepo-ng/_/php2shell_install/install.cmd'
    install_flags: '-Package apache -Version 2.4.69 -Uri https://www.apachelounge.com/download/VS18/binaries/httpd-2.4.69-261002-Win64-VS18.zip -Sha256 77d715d0d9cee731e2251e7ddc2090a7a8e6d41fedef2e9827cd918593c5a652'
    uninstaller: 'C:\ProgramData\SaltPHP2Shell\install.cmd'
    uninstall_flags: '-Action Remove -Package apache'
    cache_dir: true
    msiexec: false
{% endif %}

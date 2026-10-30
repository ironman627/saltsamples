# PHP Windows x64 Thread Safe build for the isolated PHP2Shell lab.
# 8.3.36.1 records upstream rebuild 8.3.36-1; the engine reports 8.3.36.
# Source/checksum: https://www.php.net/downloads.php?os=windows&version=8.3
{% if grains.get('cpuarch', '') | lower in ['amd64', 'x86_64'] %}
php83:
  '8.3.36.1':
    full_name: 'PHP 8.3 (Salt Lab x64 TS)'
    installer: 'salt://win/repo-ng/salt-winrepo-ng/_/php2shell_install/install.cmd'
    install_flags: '-Package php -Version 8.3.36.1 -Uri https://downloads.php.net/~windows/releases/archives/php-8.3.36-1-Win32-vs16-x64.zip -Sha256 126dd3cc8c19df5085b9420b2bc74ed591de3d98528858c52fc42739b7bba92e'
    uninstaller: 'C:\ProgramData\SaltPHP2Shell\install.cmd'
    uninstall_flags: '-Action Remove -Package php'
    cache_dir: true
    msiexec: false
{% endif %}

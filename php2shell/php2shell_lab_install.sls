{# Optional lab provisioning. Never included by identify/patch. Does not add
   repositories, open firewall ports, configure a PHP application or exploit it. #}
{% set cfg = salt['pillar.get']('php2shell', {}) %}
{% set lab = cfg.get('lab', {}) %}
{% set windows = grains.get('kernel') == 'Windows' or grains.get('os_family') == 'Windows' %}
{% set family = grains.get('os_family', '') %}
{% set branch = lab.get('php_branch', '') %}
{% set versions = lab.get('package_versions', {}) %}
{% set problems = [] %}
{% set win = cfg.get('windows', {}) %}
{% set windows_packages = [] %}
{% for package, role in win.get('packages', {}).items() %}
  {% if role in ['php', 'apache'] %}{% do windows_packages.append(package) %}{% endif %}
{% endfor %}
{% set windows_services = cfg.get('services', {}).copy() %}
{% do windows_services.update(win.get('services', {})) %}
{% set defaults = {
  'RedHat': {'packages': ['httpd', 'php', 'php-cli', 'php-common', 'php-fpm'], 'services': ['php-fpm', 'httpd']},
  'Debian': {'packages': ['apache2', 'php' ~ branch ~ '-common', 'php' ~ branch ~ '-cli', 'php' ~ branch ~ '-fpm'], 'services': ['php' ~ branch ~ '-fpm', 'apache2']},
  'Suse': {'packages': ['apache2', 'php8', 'php8-fpm'], 'services': ['php-fpm', 'apache2']}
} %}
{% set profile = {'packages': windows_packages, 'services': windows_services.keys() | list} if windows else defaults.get(family, {}) %}
{% set packages = lab.get('packages', profile.get('packages', [])) %}
{% set services = lab.get('services', profile.get('services', [])) %}
{% set exercise = lab.get('exercise_mitigation', false) %}
{% set ini_files = cfg.get('upload_progress', {}).get('ini_files', []) if exercise else [] %}
{% if versions is not mapping %}
  {% do problems.append('lab:package_versions must be a mapping of package names to exact versions.') %}
  {% set versions = {} %}
{% endif %}
{# Windows provisioning reuses the remediation package/version mappings.
   Explicit lab pins override targets; only selected packages receive targets. #}
{% if windows %}
  {% set targets = win.get('target_versions', {}) %}
  {% if targets is not mapping %}
    {% do problems.append('windows:target_versions must be a mapping of package names to exact versions.') %}
  {% elif packages is sequence and packages is not string and packages is not mapping %}
    {% set resolved_versions = {} %}
    {% for package in packages %}
      {% if package is string and package in targets %}
        {% do resolved_versions.update({package: targets[package]}) %}
      {% endif %}
    {% endfor %}
    {% do resolved_versions.update(versions) %}
    {% set versions = resolved_versions %}
  {% endif %}
{% endif %}
{% if not lab.get('enabled', false) %}
  {% do problems.append('Lab installation is disabled. Set php2shell:lab:enabled on a dedicated test minion.') %}
{% elif not windows and (grains.get('kernel') != 'Linux' or family not in defaults) %}
  {% do problems.append('Supported lab platforms: Windows, Debian/Ubuntu, RedHat-family and SUSE Linux.') %}
{% endif %}
{% if family == 'Debian' and not lab.get('packages') and (branch | regex_search('^[0-9]+[.][0-9]+$')) is none %}
  {% do problems.append('Set lab:php_branch to the branch available in your Debian/Ubuntu repositories, for example 8.3.') %}
{% endif %}
{% if packages is string or packages is mapping or packages is not sequence or not packages %}
  {% do problems.append('lab:packages must be a nonempty list; Windows requires your Winrepo package names.') %}
{% else %}
  {% for package in packages %}
    {% if package is not string %}
      {% do problems.append('Every lab package name must be a string.') %}
    {% elif windows and package in versions and (versions[package] | string | regex_search('^[0-9]+[.][0-9]+[.][0-9]+(?:[.][0-9]+)?$')) is none %}
      {% do problems.append(package ~ ': pinned Windows versions must be exact numeric versions present in Winrepo.') %}
    {% endif %}
  {% endfor %}
{% endif %}
{% if services is string or services is mapping or services is not sequence %}
  {% do problems.append('lab:services must be a list of actual service names.') %}
{% elif windows and lab.get('start_services', false) and not services %}
  {% do problems.append('Supply Windows lab:services before requesting service startup; IIS must be provisioned separately if used.') %}
{% else %}
  {% for service in services %}
    {% if service is not string or not service %}{% do problems.append('Every lab service name must be a nonempty string.') %}{% endif %}
  {% endfor %}
{% endif %}
{% if exercise and (ini_files is string or ini_files is mapping or ini_files is not sequence or not ini_files) %}
  {% do problems.append('exercise_mitigation requires upload_progress:ini_files for the lab runtime.') %}
{% elif exercise %}
  {% for path in ini_files %}
    {% if path is not string or not path.lower().endswith('.ini') or path.lower().endswith('.user.ini') %}
      {% do problems.append('Use startup PHP INI paths for the mitigation exercise, not .user.ini or server configuration.') %}
    {% endif %}
  {% endfor %}
{% endif %}

{% if problems %}
php2shell_lab_install_blocked:
  test.fail_without_changes:
    - name: {{ problems | join(' ') | tojson }}
{% else %}
php2shell_lab_packages:
  {{ 'pkg.latest' if not versions and lab.get('install_latest', true) else 'pkg.installed' }}:
    - pkgs:
{% for package in packages %}
{% if package in versions %}
      - {{ package | tojson }}: {{ versions[package] | string | tojson }}
{% else %}
      - {{ package | tojson }}
{% endif %}
{% endfor %}
    - refresh: true
{% if not windows %}
    - skip_verify: false
{% if cfg.get('fromrepo') %}
    - fromrepo: {{ cfg.fromrepo | tojson }}
{% endif %}
{% endif %}

{% set changed_files = [] %}
{% for path in ini_files %}
{% do changed_files.append({'file': 'php2shell_lab_php_ini_' ~ loop.index}) %}
{% do changed_files.append({'file': 'php2shell_lab_upload_progress_' ~ loop.index}) %}
{# file.replace has no source argument. Seed missing files with file.managed,
   preserving package-provided INI settings, then apply the lab reset below. #}
php2shell_lab_php_ini_{{ loop.index }}:
  file.managed:
    - name: {{ path | tojson }}
    - source: salt://php2shell/files/php.ini
    - replace: false
    - makedirs: true
{% if not windows %}
    - user: root
    - group: root
    - mode: '0644'
{% endif %}
    - require:
      - pkg: php2shell_lab_packages

php2shell_lab_upload_progress_{{ loop.index }}:
  file.replace:
    - name: {{ path | tojson }}
    - pattern: '(?im)^[ \t]*session[.]upload_progress[.]enabled[ \t]*=[^\r\n]*'
    - repl: 'session.upload_progress.enabled = 1'
    - append_if_not_found: true
    - backup: '.php2shell-lab.bak'
    - require:
      - file: php2shell_lab_php_ini_{{ loop.index }}
{% endfor %}

{% if lab.get('start_services', false) %}
{% for service in services %}
php2shell_lab_service_{{ loop.index }}:
  service.running:
    - name: {{ service | tojson }}
    - watch: {{ ([{'pkg': 'php2shell_lab_packages'}] + changed_files) | tojson }}
{% endfor %}
{% endif %}
{% endif %}

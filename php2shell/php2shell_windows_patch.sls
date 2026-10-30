{# Included automatically by php2shell_patch on Windows. Installers/wrappers
   in Winrepo must preserve configuration and handle locked runtime files. #}
{% from 'php2shell/php2shell_map.jinja' import cfg, is_windows, inventory, errors, services, service_states, mitigation with context %}
{% set win = cfg.get('windows', {}) %}
{% set managed = inventory | selectattr('managed', 'equalto', true) | list if is_windows else [] %}
{% if not is_windows %}{% do errors.append('This state requires Windows; use php2shell.php2shell_patch for automatic platform selection.') %}{% endif %}
{% set targets = win.get('target_versions', {}) %}
{% set updates = [] %}
{% set pools = win.get('iis_apppools', []) %}
{% set running_pools = [] %}
{% set apache_php = [] %}
{% for item in inventory %}
  {% if (item.package | lower | regex_search('php[0-9]+apache2_4[.]dll$')) is not none %}{% do apache_php.append(item.package) %}{% endif %}
{% endfor %}
{% for item in managed %}
  {% set target = targets.get(item.package, '') %}
  {% if item.status in ['unknown_baseline', 'uncomparable'] or item.needs_review %}
    {# Inventory already records the error. Do not compare invalid versions. #}
  {% elif target %}
    {% if (target | regex_search('^[0-9]+[.][0-9]+[.][0-9]+(?:[.][0-9]+)?$')) is none %}
      {% do errors.append(item.package ~ ': target_versions must specify an exact numeric Winrepo version.') %}
    {% elif item.minimum and not salt['pkg.compare_versions'](ver1=target, oper='>=', ver2=item.minimum) %}
      {% do errors.append(item.package ~ ': requested Winrepo target is below the security minimum.') %}
    {% elif salt['pkg.compare_versions'](ver1=item.installed, oper='<', ver2=target) %}
      {% if item.component == 'php' and item.installed.split('.')[:2] != target.split('.')[:2] %}
        {% do errors.append(item.package ~ ': PHP branch migrations require a separate deployment.') %}
      {% else %}
        {% do updates.append({'package': item.package, 'version': target}) %}
      {% endif %}
    {% endif %}
  {% elif item.status != 'meets_baseline' %}
    {% do errors.append(item.package ~ ': set windows:target_versions to an approved exact version present in Winrepo.') %}
  {% endif %}
{% endfor %}
{% if (updates or mitigation.pending or cfg.get('force_restart', false)) and not services and not pools and not win.get('no_web_workers', false) %}
  {% do errors.append('Configure Windows services/config tests or IIS application pools to replace web workers; use no_web_workers only for a CLI-only deployment.') %}
{% endif %}
{% if apache_php and (updates or mitigation.pending or cfg.get('force_restart', false)) and not services %}
  {% do errors.append('An Apache PHP module was detected: configure its Apache Windows service and httpd.exe config test; IIS recycling or no_web_workers cannot replace mod_php workers.') %}
{% endif %}
{% if pools and ('win_iis.restart_apppool' not in salt or 'win_iis.list_apppools' not in salt) %}
  {% do errors.append('IIS management functions are unavailable; install/enable the Salt win_iis prerequisites.') %}
{% elif pools %}
  {% set existing_pools = salt['win_iis.list_apppools']() %}
  {% for pool in pools %}
    {% if pool not in existing_pools %}{% do errors.append(pool ~ ': configured IIS pool does not exist.') %}{% endif %}
    {% if pool in existing_pools and existing_pools[pool].get('state', '') | lower == 'started' %}{% do running_pools.append(pool) %}{% endif %}
  {% endfor %}
{% endif %}
{% for service in services %}
  {% if not salt['service.available'](service) %}{% do errors.append(service ~ ': configured Windows service does not exist.') %}{% endif %}
{% endfor %}
{% set update_names = updates | map(attribute='package') | list %}
{% for item in inventory %}
  {% if not item.managed | default(true) and item.status == 'below_baseline' %}
    {% if item.owner not in update_names %}
      {% do errors.append(item.package ~ ': binary is below baseline but its owning package is not scheduled for update; repair the package deployment.') %}
    {% endif %}
  {% endif %}
{% endfor %}
{% if errors %}
php2shell_windows_patch_blocked:
  test.fail_without_changes:
    - name: {{ errors | join(' ') | tojson }}
{% elif not managed %}
php2shell_windows_no_managed_runtime:
  test.nop:
    - name: No managed PHP or Apache installation detected in the checked Windows inventory.
{% else %}
{% if updates %}
php2shell_windows_fixed_packages:
  pkg.installed:
    - pkgs:
{% for item in updates %}
      - {{ item.package | tojson }}: {{ item.version | tojson }}
{% endfor %}
    - refresh: true
    - allow_updates: true
{% else %}
php2shell_windows_fixed_packages:
  test.nop:
    - name: Managed packages meet configured targets. Apache without a security minimum is not CVE-certified.
{% endif %}
{% set package_type = 'pkg' if updates else 'test' %}
{{ mitigation.states([{package_type: 'php2shell_windows_fixed_packages'}]) }}
{% if updates or mitigation.pending or cfg.get('force_restart', false) %}
{{ service_states([{package_type: 'php2shell_windows_fixed_packages'}], prefix='php2shell_windows', force=true) }}
{% endif %}
{% for pool in running_pools %}
{% if updates or mitigation.pending or cfg.get('force_restart', false) %}
php2shell_windows_iis_pool_{{ loop.index }}:
  module.run:
    - win_iis.restart_apppool:
      - name: {{ pool | tojson }}
    - require:
      - {{ package_type }}: php2shell_windows_fixed_packages
      - test: php2shell_upload_progress
{% for prerequisite in mitigation.file_requisites %}
      - {{ prerequisite | tojson }}
{% endfor %}
{% endif %}
{% endfor %}
{% endif %}

{# Patch installed runtime packages using minimums derived from their branch.
   Repositories/module streams must be constrained to the intended branch.
   >= constraints accept newer packages and prevent intentional downgrades.
   Unsupported/EOL branches without vendor overrides stop before any changes. #}
{% if grains.get('kernel') == 'Windows' or grains.get('os_family') == 'Windows' %}
include:
  - php2shell.php2shell_windows_patch
{% else %}
{% from 'php2shell/php2shell_map.jinja' import cfg, inventory, errors, service_states, mitigation with context %}
{% set fixed = inventory | rejectattr('minimum', 'equalto', '') | list %}
{% set apache_updates = inventory | selectattr('status', 'equalto', 'vendor_advisory_required') | list %}
{% set package_states = [] %}

{% if errors %}
php2shell_patch_blocked:
  test.fail_without_changes:
    - name: {{ errors | join(' ') | tojson }}
{% elif not inventory %}
php2shell_no_packaged_runtime:
  test.nop:
    - name: No matching OS packages found. Review containers and custom runtimes separately.
{% else %}
{% if fixed %}
{% do package_states.append('php2shell_fixed_packages') %}
php2shell_fixed_packages:
  pkg.installed:
    - pkgs:
{% for item in fixed %}
      - {{ item.package | tojson }}: {{ ('>=' ~ item.minimum) | tojson }}
{% endfor %}
    - refresh: true
    - ignore_epoch: false
    - skip_verify: false
{% if cfg.get('fromrepo') %}
    - fromrepo: {{ cfg.fromrepo | tojson }}
{% endif %}
{% endif %}

{% if apache_updates %}
{% do package_states.append('php2shell_apache_repository_updates') %}
php2shell_apache_repository_updates:
  pkg.latest:
    - pkgs:
{% for item in apache_updates %}
      - {{ item.package | tojson }}
{% endfor %}
    - refresh: true
    - skip_verify: false
{% if cfg.get('fromrepo') %}
    - fromrepo: {{ cfg.fromrepo | tojson }}
{% endif %}
{% endif %}

{% set prerequisites = [] %}
{% for state_id in package_states %}{% do prerequisites.append({'pkg': state_id}) %}{% endfor %}
{{ mitigation.states(prerequisites) }}
{{ service_states(prerequisites, force=cfg.get('force_restart', false)) }}
{% endif %}
{% endif %}

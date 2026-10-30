{# Read-only PHP2Shell assessment of OS-managed PHP runtime packages.
   Apache alone does not expose a system to PHP2Shell. Containers/source
   builds, web reachability and running worker versions are outside scope. #}
{% from 'php2shell/php2shell_map.jinja' import supported, is_windows, php_inventory, windows_unknown, mitigation with context %}
{% set php_issues = [] %}
{% for item in php_inventory %}
  {% if item.status != 'meets_baseline' or item.needs_review | default(false) %}
    {% do php_issues.append(item.package) %}
  {% endif %}
{% endfor %}
{% if not supported %}
  {% set message = 'UNDETERMINED - unsupported platform.' %}
{% elif windows_unknown %}
  {% set message = 'UNDETERMINED - Windows runtime inventory or version information is incomplete.' %}
{% elif not php_inventory %}
  {% set message = 'NOT EXPOSED - no PHP runtime detected in the checked Windows locations.' if is_windows else 'NOT EXPOSED - no OS-managed PHP runtime detected.' %}
{% elif php_issues %}
  {% set message = 'NEEDS PATCHING - PHP packages are below the fixed baseline or require vendor-fix verification.' %}
{% elif mitigation.problems %}
  {% set message = 'UNDETERMINED - earlier PHP fixes present; CVE-2026-115560 configuration coverage needs review.' %}
{% elif mitigation.pending %}
  {% set message = 'NEEDS MITIGATION - CVE-2026-115560: disable session.upload_progress.enabled and replace affected workers.' %}
{% elif not mitigation.not_applicable %}
  {% set message = 'MITIGATED - earlier PHP fixes present; CVE-2026-115560 workaround configured. Verify active workers.' %}
{% else %}
  {% set message = 'ALREADY PATCHED - detected PHP runtimes meet the fixed baseline.' if is_windows else 'ALREADY PATCHED - installed PHP packages meet the fixed baseline.' %}
{% endif %}

php2shell_package_assessment:
  test.configurable_test_state:
    - name: {{ 'PHP2Shell status (Windows packages and runtime locations)' if is_windows else 'PHP2Shell status (Linux OS packages)' }}
    - changes: false
    - result: {{ supported and not windows_unknown and not php_issues and not mitigation.problems and not mitigation.pending }}
    - comment: {{ message | tojson }}

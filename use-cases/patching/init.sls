# this state patches both Linux and Windows-based systems.
# based on the patching Status state.

{% set platform = salt['grains.get']('kernel') %}

{% set patched = salt['grains.get']('Patched', False ) %}

{% if patched == False %}
{% if platform == 'Linux' %}
update_system:
  pkg.uptodate:
    - name: update system

set_patched_grain_true:
  grains.present:
    - name: Patched
    - value: True
    - require:
      - update_system
{% else %}
patch_windows:
  wua.uptodate:
    - skip_reboot: False

set_patched_grain_true:
  grains.present:
    - name: Patched
    - value: True
    - require:
      - patch_windows
{% endif %}
{% else %}

system_exempt:
  test.configurable_test_state:
    - name: System patched
    - changes: False
    - result: True
    - comment: System is up to date already

{% endif %}

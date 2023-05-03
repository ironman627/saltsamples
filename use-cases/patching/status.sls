# This state will check if a system needs to be updated/patched
# It will then set a new "Patched" grain to either True or False
# Can be applied to either Windows or Linux based systems

{% set platform = salt['grains.get']('kernel') %}

{% if platform == 'Linux' %}
{% set status = salt['pkg.list_upgrades']() %}
{% else %}
{% set status = salt['win_wua.list'](summary=True, install=False, skip_installed=False) %}
{% endif %}

{% if status == {} %}

set_patched_grain_true:
  grains.present:
    - name: Patched
    - value: True

{% elif status == 0 %}
set_patched_grain_true:
  grains.present:
    - name: Patched
    - value: True

{% else %}
set_patched_grain_false:
  grains.present:
    - name: Patched
    - value: False

{% endif %}
 
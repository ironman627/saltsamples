# Map file of new Minion systems to onboard 

{% import_yaml 'onboarding/minion_list.yaml' as min_list %}

{% set minions = min_list['minions'] %}

{% for minion in minions %}
{% if 'win' in minion %}
create_{{ minion }}_profile:
  file.managed:
    - name: /etc/salt/cloud.profiles.d/{{ minion }}.conf
    - source: salt://onboarding/win_profile.conf
    - template: jinja
    - minionid: {{ minion }}
    - ssh_host: {{ minions[minion]['ip_address'] }}
    - ssh_username: {{ minions[minion]['user'] }}
    - password: {{ minions[minion]['password'] }}

add_{{minion}}_to_winmap:
  file.append:
    - name: /etc/salt/cloud.maps.d/windows.map
    - source: salt://onboarding/win_tmpl.map
    - template: jinja
    - defaults:
        profile_name: {{ minion }}
        minionid: {{ minion }}
{% else %}
create_{{ minion }}_profile:
  file.managed:
    - name: /etc/salt/cloud.profiles.d/{{ minion }}.conf
    - source: salt://onboarding/profile.conf
    - template: jinja
    - minionid: {{ minion }}
    - ssh_host: {{ minions[minion]['ip_address'] }}
    - ssh_username: {{ minions[minion]['user'] }}
    - password: {{ minions[minion]['password'] }}

add_{{minion}}_to_linmap:
  file.append:
    - name: /etc/salt/cloud.maps.d/linux.map
    - source: salt://onboarding/linux_tmpl.map
    - template: jinja
    - defaults:
        profile_name: {{ minion }}
        minionid: {{ minion }}

{% endif %}
{% endfor %}

create_provider:
  file.managed:
    - name: /etc/salt/cloud.providers.d/provider.conf
    - source: salt://onboarding/provider.conf


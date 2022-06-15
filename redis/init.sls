# Chapter 8 Lab - /srv/salt/redis/init.sls
{% import_yaml 'redis/map.yaml' as settings %}

install_redis:
  pkg.installed:
    - name: redis

configure_redis:
  file.managed:
    - name: /etc/redis.conf
    - source: salt://redis/files/redis.conf
    - template: jinja
    - port: {{ settings.port }}
    - bind: {{ settings.bind }}
    - dir: {{ settings.dir }}
    - require:
      - pkg: install_redis

start_redis:
  service.running:
    - name: redis
    - enable: True
    - watch:
      - file: configure_redis

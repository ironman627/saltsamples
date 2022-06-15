# Lab Chap. 8 - /srv/salt/httpd/init.sls
{% import_yaml 'httpd/map.yaml' as osmap %}
{% set apache = salt['grains.filter_by'](osmap) %}


install_httpd:
  pkg.installed:
    - name: {{ apache.name }}

configure_httpd:
  file.managed:
    - name: {{ apache.httpfile }}
    - source: {{ apache.source_httpfile }}
    - template: jinja
    - defaults:
        admin_email: {{ apache.admin_email }}
        group: {{ apache.group }}
        http_port: {{ apache.http_port }}
        user: {{ apache.user }}    
    - require:
      - pkg: install_httpd

start_httpd:
  service.running:
    - name: {{ apache.name }}
    - watch:
      - file: configure_httpd

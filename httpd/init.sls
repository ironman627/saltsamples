# Lab Chap. 7 - /srv/salt/httpd/init.sls
include:
  - apachetop

install_httpd:
  pkg.installed:
    - name: httpd

configure_httpd:
  file.managed:
    - name: /etc/httpd/conf/httpd.conf
    - source: salt://httpd/files/httpd.conf

start_httpd:
  service.running:
    - name: httpd
    - enable: True
    - require:
      - pkg: install_httpd
    - watch:
      - file: configure_httpd

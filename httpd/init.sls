# Lab Chap. 6 - /srv/salt/httpd/init.sls file
install_httpd:
  pkg.installed:
    - name: httpd

start_httpd:
  service.running:
    - name: httpd
    - enable: True

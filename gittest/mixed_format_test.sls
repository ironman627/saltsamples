# Test file showing difference between old format and proper Salt states

# This is OLD FORMAT (will be converted) - file path as state ID
/etc/myapp/config.conf:
  file.managed:
    - source: salt://myapp/config.conf

# This is PROPER FORMAT (will NOT be converted) - proper state ID with module
install_nginx:
  pkg.installed:
    - name: nginx

configure_nginx:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - source: salt://nginx/nginx.conf

# Another OLD FORMAT (will be converted) - Windows path as state ID  
C:\Windows\System32\config.ini:
  file.managed:
    - source: salt://windows/config.ini
# Test file showing difference between old format and proper Salt states

# This is OLD FORMAT (will be converted) - file path as state ID
# Converted from old format: /etc/myapp/config.conf:
etc_myapp_config_conf:
  file.managed:
    - name: /etc/myapp/config.conf
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
# Converted from old format: C:\Windows\System32\config.ini:
Windows_System32_config_ini:
  file.managed:
    - name: C:\Windows\System32\config.ini
    - source: salt://windows/config.ini
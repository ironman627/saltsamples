# File.managed shift to best practice format
# /srv/salt/test/best

# Converted from old format: /srv/salt/test/best/old.sls:
srv_salt_test_best_old_sls:
  file.managed:
    - name: /srv/salt/test/best/old.sls
    - source: salt://test/best/old_format.sls
    - template: jinja


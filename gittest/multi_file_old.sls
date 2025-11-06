# File.managed shift to best practice format
# /srv/salt/test/best

srv_salt_test_best_old_sls:
  file.absent:
    - name: /srv/salt/test/best/old.sls


srv_salt_test_best_old_sls_2:
  file.managed:
    - name: /srv/salt/test/best/old.sls
    - source: salt://test/best/old_format.sls
    - template: jinja


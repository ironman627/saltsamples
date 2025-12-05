# State to set a custom grain for devtops environment testing
staging_grain:
  grains.present:
    - name: devtops
    - value: staging

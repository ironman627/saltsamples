# Check the version of a package and patch to the latest version.
# Sample command: salt <minionid> state.sls patch_pkg.sls pillar='{"package": "gzip"}' test=1
# running the above with "test=1" allows you to see if an update is needed for the package before actually updating it.

{% set package = salt['pillar.get']('package') %}

patch_{{ package }}:
  pkg.latest:
    - name: {{ package }}

# The following stanza is if you need to install a specific version of a package.
# Sample command: salt <minionid> state.sls patch_pkg.sls pillar='{"package": "gzip", "specific_version": "version_you_need"}' test=1
# Replace the above active code with the following lines:

# {% set package = salt['pillar.get']('package') %}
# {% set specific_version = salt['pillar.get']('specific_version') %}
# patch_{{ package }}:
#   pkg.installed:
#     - name: {{ package }}
#     - version: {{ specific_version }}
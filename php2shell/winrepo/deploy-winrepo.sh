#!/bin/bash
# Run on the Salt master from a copy of this directory. Does not install packages.
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
target_dir=/srv/salt/win/repo-ng/salt-winrepo-ng/_
test -d "$target_dir" || { echo "Expected existing Winrepo checkout: $target_dir" >&2; exit 1; }
backup_dir="$(mktemp -d /var/tmp/php2shell-winrepo-backup.XXXXXXXX)"
for relative in php83.sls apache24.sls php2shell_install/install.cmd php2shell_install/install.ps1; do
    if test -e "$target_dir/$relative"; then
        mkdir -p -- "$backup_dir/$(dirname -- "$relative")"
        cp -p -- "$target_dir/$relative" "$backup_dir/$relative"
    fi
    install -D -m 0644 -- "$source_dir/$relative" "$target_dir/$relative"
done
echo "Created php83.sls and apache24.sls plus their shared ZIP installer wrapper."
echo "Backups: $backup_dir"
echo "Next: salt 'salt-win01-rr' pkg.refresh_db"
echo "Then: salt 'salt-win01-rr' pkg.list_available php83 apache24"

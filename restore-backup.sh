#!/bin/bash
# Wrapper - run scripts/restore-backup.sh
exec "$(dirname "$0")/scripts/restore-backup.sh" "$@"

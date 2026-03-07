#!/bin/bash
# Wrapper - run scripts/uninstall.sh
exec "$(dirname "$0")/scripts/uninstall.sh" "$@"

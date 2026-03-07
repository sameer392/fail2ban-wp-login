#!/bin/bash
# Wrapper - run scripts/update-whitelist.sh
exec "$(dirname "$0")/scripts/update-whitelist.sh" "$@"

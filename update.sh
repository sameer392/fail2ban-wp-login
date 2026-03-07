#!/bin/bash
# Wrapper - run scripts/update.sh
exec "$(dirname "$0")/scripts/update.sh" "$@"

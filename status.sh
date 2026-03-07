#!/bin/bash
# Wrapper - run scripts/status.sh
exec "$(dirname "$0")/scripts/status.sh" "$@"

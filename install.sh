#!/bin/bash
# Wrapper - run scripts/install.sh
exec "$(dirname "$0")/scripts/install.sh" "$@"

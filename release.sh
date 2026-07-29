#!/bin/sh

set -eu

script_directory=$(
	CDPATH= cd -- "$(dirname -- "$0")" &&
		pwd
)
cd "$script_directory"

exec "${MAKE:-make}" release "$@"

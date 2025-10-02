#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -u -e -o pipefail

if [[ $# -ne 1 ]]; then
	echo "usage $(basename -- "${BASH_SOURCE[0]}") <kernel-source>" >&2
	exit 1
fi

LANDLOCK_H="$(readlink -f -- "$1")/include/uapi/linux/landlock.h"

if [[ ! -f "${LANDLOCK_H}" ]]; then
	echo "File not found: ${LANDLOCK_H}" >&2
	exit 1
fi

cd "$(dirname "${BASH_SOURCE[0]}")"

MSRV="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' ../../Cargo.toml)"

for ARCH in x86_64 i686; do
	bindgen \
		--rust-target "${MSRV}" \
		--ctypes-prefix="::std::os::raw" \
		-o "landlock_${ARCH}.rs" \
		"${LANDLOCK_H}" \
		-- \
		--target="${ARCH}-linux-gnu"
done

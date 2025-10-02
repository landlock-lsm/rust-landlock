#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -u -e -o pipefail

if [[ $# -ne 1 ]]; then
	echo "usage $(basename -- "${BASH_SOURCE[0]}") <kernel-source>" >&2
	exit 1
fi

HEADER="$(readlink -f -- "$1")/include/uapi/linux/landlock.h"

if [[ ! -f "${HEADER}" ]]; then
	echo "File not found: ${HEADER}" >&2
	exit 1
fi

cd "$(dirname "${BASH_SOURCE[0]}")"

MSRV="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' ../../Cargo.toml)"

bindgen_landlock() {
	local arch="$1"
	local output="$2"
	shift 2

	bindgen \
		"$@" \
		--rust-target "${MSRV}" \
		--allowlist-type "landlock_.*" \
		--allowlist-var "LANDLOCK_.*" \
		--no-doc-comments \
		--no-derive-default \
		--output "${output}" \
		"${HEADER}" \
		-- \
		--target="${arch}-linux-gnu"
}

for ARCH in x86_64 i686; do
	echo "Generating bindings with tests for ${ARCH}."
	bindgen_landlock "${ARCH}" "landlock_${ARCH}.rs"
done

# The Landlock ABI is architecture-agnostic (except for std::os::raw and memory
# alignment).
echo "Generating bindings without tests."
bindgen_landlock x86_64 "landlock_all.rs" --no-layout-tests

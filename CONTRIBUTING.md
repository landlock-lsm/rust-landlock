# Contributing

Thanks for your interest in contributing to rust-landlock!

## Testing vs kernel ABI

The Landlock functionality exposed differs between kernel versions. Based on
the Landlock ABI version of the running system, rust-landlock runs different
subsets of tests. For local development, running `cargo test` will test against
your currently running kernel version (and the Landlock ABI that it ships).
However, this may result in some tests being skipped.

To fully test a change, it should be verified against a range of ABI versions.
This is done by the Github Actions CI, but doing so locally is challenging.

Using the `LANDLOCK_CRATE_TEST_ABI` variable, the tested ABI version can be
overridden. For more details, take a look at the comment in
[`compat.rs:current_kernel_abi()`][current-kernel-abi].

For more information about Landlock ABIs, see: [enum ABI][enum-abi]

[current-kernel-abi]: https://github.com/landlock-lsm/rust-landlock/blob/main/src/compat.rs
[enum-abi]: https://landlock.io/rust-landlock/landlock/enum.ABI.html

## Licensing & DCO

rust-landlock is double-licensed under the terms of [Apache 2.0][apache-2.0]
and [MIT][mit].

All changes submitted to rust-landlock must be [signed off][dco].

[apache-2.0]: https://spdx.org/licenses/Apache-2.0.html
[mit]: https://spdx.org/licenses/MIT.html
[dco]: https://github.com/apps/dco

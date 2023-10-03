# Landlock changelog

## [v0.3.0](https://github.com/landlock-lsm/rust-landlock/releases/tag/v0.3.0)

### New API

Add support for Landlock ABI 3: control truncate operations with the new
[`AccessFs::Truncate`](https://landlock.io/rust-landlock/landlock/enum.AccessFs.html#variant.Truncate)
right ([PR #40](https://github.com/landlock-lsm/rust-landlock/pull/40)).

Revamp the compatibility handling and add a new
[`set_compatibility()`](https://landlock.io/rust-landlock/landlock/trait.Compatible.html#method.set_compatibility)
method for `Ruleset`, `RulesetCreated`, and `PathBeneath`.
We can now fine-tune the compatibility behavior according to the running kernel
and then the supported features thanks to three compatible levels:
best effort, soft requirement and hard requirement
([PR #12](https://github.com/landlock-lsm/rust-landlock/pull/12)).

Add a new [`AccessFs::from_file()`](https://landlock.io/rust-landlock/landlock/enum.AccessFs.html#method.from_file)
helper ([commit 0b3238c6dd70](https://github.com/landlock-lsm/rust-landlock/commit/0b3238c6dd70)).

### Deprecated API

Deprecate the [`set_best_effort()`](https://landlock.io/rust-landlock/landlock/trait.Compatible.html#method.set_best_effort)
method and replace it with `set_compatibility()`
([PR #12](https://github.com/landlock-lsm/rust-landlock/pull/12)).

Deprecate [`Ruleset::new()`](https://landlock.io/rust-landlock/landlock/struct.Ruleset.html#method.new)
and replace it with `Ruleset::default()`
([PR #44](https://github.com/landlock-lsm/rust-landlock/pull/44)).

### Breaking changes

We now check that a ruleset really handles at least one access right,
which can now cause `Ruleset::create()` to return an error if the ruleset compatibility level is
`HardRequirement` or `set_best_effort(false)`
([commit 95addc13b4a8](https://github.com/landlock-lsm/rust-landlock/commit/95addc13b4a8)).

We now check that access rights passed to `add_rule()` make sense according to the file type.
To handle most use cases,
`path_beneath_rules()` now automatically check and downgrade access rights for files
(i.e. remove superfluous directory-only access rights,
 [commit 8e47940b3722](https://github.com/landlock-lsm/rust-landlock/commit/8e47940b3722)).

### Testing

Test coverage in the CI is greatly improved by running all tests on all relevant kernel versions:
Linux 5.10, 5.15, 6.1, and 6.4
([PR #41](https://github.com/landlock-lsm/rust-landlock/pull/41)).

Run each test in a dedicated thread to avoid inconsistent behavior
([PR #46](https://github.com/landlock-lsm/rust-landlock/pull/46)).

## [v0.2.0](https://github.com/landlock-lsm/rust-landlock/releases/tag/v0.2.0)

This is the first major release of this crate.
It brings a high-level interface to the Landlock kernel interface.

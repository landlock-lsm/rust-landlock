# Landlock crate

This version is not stable yet.

The [published crate](https://crates.io/crates/landlock) may not be up-to-date because of the ongoing work to design a better [best-effort security API](https://github.com/landlock-lsm/rust-landlock/pull/5).
However, you can still use this repository to experiment with Landlock.

More information about Landlock can be found in the [official website](https://landlock.io).

## Compatibility

### Execute as much as possible

Compatibility should only be about the system supporting Landlock, not about the required action dependencies (e.g., opening a file to add it to a rule).
This enables to check that the use of Landlock would be OK if supported, instead of ignoring files that should be used in a Landlock ruleset.
When running the same program on different environments, this helps catch issues with the assumed context (e.g., whether a directory hierarchy exists or not).

### API

To make it easier to migrate to a new version of this library, we use the builder pattern and design objects to require the minimal set of method arguments.
Some `enum` are marked as `non_exhaustive` to enable backward-compatible future evolutions.

### Test strategy

Developers should test their sandboxed applications with a compatible kernel and `Support::Required` set to make sure everything works as expected.
However, applications should use the default `Support::Optional` for any not fully controlled environments (e.g., Linux distributions, customers).

### Rational for the current interface

The simple approach is to expose the Landlock ABI version and ask the developer to manage the related implication explicitly.
This requires developers to grasp all the potential behavior changes over time, which will eventually lead to issues.

Instead, we can ask developers to identify optional (best-effort) or required features.
This make more sense because this directly relies on the access-control semantic.
It makes the library more difficult to implement but simpler to use for most use cases (because there is no manual ABI version management), and easier to audit for most complex requirements (because they are explicitly set as required, instead on relying on manual ABI version mapping).

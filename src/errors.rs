use crate::{AccessFs, BitFlags};
use enumflags2::BitFlag;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Maps to all errors that can be returned by a ruleset action.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RulesetError<T>
where
    T: BitFlag,
{
    #[error(transparent)]
    HandleFs(#[from] HandleFsError),
    #[error(transparent)]
    CreateRuleset(#[from] CreateRulesetError),
    #[error(transparent)]
    AddRule(#[from] AddRuleError<T>),
    #[error(transparent)]
    RestrictSelf(#[from] RestrictSelfError),
    #[error(transparent)]
    PathFd(#[from] PathFdError),
}

#[test]
fn ruleset_error_breaking_change() {
    use crate::*;

    // Generics are part of the API and modifying them can lead to a breaking change.
    let _: RulesetError<AccessFs> = RulesetError::HandleFs(HandleFsError::Compat(
        CompatError::Access(AccessError::Empty),
    ));

    // FIXME: This should not be possible.
    use enumflags2::bitflags;
    #[bitflags]
    #[repr(u64)]
    #[derive(Copy, Clone)]
    enum WrongAccess {
        Foo,
    }
    let _: RulesetError<WrongAccess> = RulesetError::HandleFs(HandleFsError::Compat(
        CompatError::Access(AccessError::Empty),
    ));
}

/// Identifies errors when updating the ruleset's handled file system access-rights.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HandleFsError {
    #[error(transparent)]
    Compat(#[from] CompatError<AccessFs>),
}

/// Identifies errors when creating a ruleset.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CreateRulesetError {
    /// The `landlock_create_ruleset()` system call failed.
    #[error("failed to create a ruleset: {source}")]
    #[non_exhaustive]
    CreateRulesetCall { source: io::Error },
}

/// Identifies errors when adding a rule to a ruleset.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AddRuleError<T>
where
    T: BitFlag,
{
    /// The `landlock_add_rule()` system call failed.
    #[error("failed to add a rule: {source}")]
    #[non_exhaustive]
    AddRuleCall { source: io::Error },
    /// The rule's access-rights are not all handled by the (requested) ruleset access-rights.
    #[error("access-rights not handled by the ruleset: {incompatible:?}")]
    UnhandledAccess {
        access: BitFlags<T>,
        incompatible: BitFlags<T>,
    },
    #[error(transparent)]
    Compat(#[from] CompatError<T>),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CompatError<T>
where
    T: BitFlag,
{
    #[error(transparent)]
    PathBeneath(#[from] PathBeneathError),
    #[error(transparent)]
    Access(#[from] AccessError<T>),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PathBeneathError {
    /// To check that access-rights are consistent with a file descriptor, a call to
    /// `RulesetCreated::add_rule()` looks at the file type with an `fstat()` system call.
    #[error("failed to check file descriptor type: {source}")]
    #[non_exhaustive]
    StatCall { source: io::Error },
    /// This error is returned by `RulesetCreated::add_rule() `if the related PathBeneath object is
    /// not set to best-effort, and if its allowed access-rights contain directory-only ones
    /// whereas the file descriptor doesn't point to a directory.
    #[error("incompatible directory-only access-rights: {incompatible:?}")]
    DirectoryAccess {
        access: BitFlags<AccessFs>,
        incompatible: BitFlags<AccessFs>,
    },
}

#[derive(Debug, Error)]
// Exhaustive enum
pub enum AccessError<T>
where
    T: BitFlag,
{
    /// The access-rights set is empty, which doesn't make sense and would be rejected by the
    /// kernel.
    #[error("empty access-right")]
    Empty,
    /// The access-rights set was forged with the unsafe `BitFlags::from_bits_unchecked()` and it
    /// contains unknown bits.
    #[error("unknown access-rights (at build time): {unknown:?}")]
    Unknown {
        access: BitFlags<T>,
        unknown: BitFlags<T>,
    },
    /// The best-effort approach was (deliberately) disabled and the requested access-rights are
    /// fully incompatible with the running kernel.
    #[error("fully incompatible access-rights: {access:?}")]
    Incompatible { access: BitFlags<T> },
    /// The best-effort approach was (deliberately) disabled and the requested access-rights are
    /// partially incompatible with the running kernel.
    #[error("partially incompatible access-rights: {incompatible:?}")]
    PartiallyCompatible {
        access: BitFlags<T>,
        incompatible: BitFlags<T>,
    },
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RestrictSelfError {
    /// The `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` system call failed.
    #[error("failed to set no_new_privs: {source}")]
    #[non_exhaustive]
    SetNoNewPrivsCall { source: io::Error },
    /// The `landlock_restrict_self() `system call failed.
    #[error("failed to restrict the calling thread: {source}")]
    #[non_exhaustive]
    RestrictSelfCall { source: io::Error },
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PathFdError {
    /// The `open()` system call failed.
    #[error("failed to open \"{path}\": {source}")]
    #[non_exhaustive]
    OpenCall { source: io::Error, path: PathBuf },
}

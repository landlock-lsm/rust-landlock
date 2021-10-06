extern crate enumflags2;

pub use enumflags2::{make_bitflags, BitFlag, BitFlags};
pub use fs::{AccessFs, PathBeneath};
pub use ruleset::{RestrictionStatus, Rule, RulesetCreated, RulesetInit};
use std::convert::{TryFrom, TryInto};
use std::io::{Error, ErrorKind};
use std::mem::replace;

mod fs;
mod ruleset;
mod uapi;

/// Version of the Landlock [ABI](https://en.wikipedia.org/wiki/Application_binary_interface).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ABI {
    V1 = 1,
}

impl ABI {
    fn new_current() -> Result<Self, Error> {
        unsafe {
            // Landlock ABI version starts at 1 but errno is only set for negative values.
            uapi::landlock_create_ruleset(
                std::ptr::null(),
                0,
                uapi::LANDLOCK_CREATE_RULESET_VERSION,
            )
        }
        .try_into()
    }

    fn is_compatible<T>(&self, minimum_version: T) -> bool
    where
        T: TryInto<Self>,
    {
        match minimum_version.try_into() {
            Ok(min) => self >= &min,
            Err(_) => false,
        }
    }
}

#[test]
fn abi_is_compatible() {
    assert!(!ABI::V1.is_compatible(-1));
    assert!(!ABI::V1.is_compatible(0));

    assert!(ABI::V1.is_compatible(1));
    assert!(ABI::V1.is_compatible(2));
}

impl TryFrom<i32> for ABI {
    type Error = Error;

    fn try_from(value: i32) -> Result<ABI, Error> {
        match value {
            // A value of 0 should not come from the kernel, but if it is the case we get an
            // Other error (or an Uncategorized error in a newer Rust std).
            n if n <= 0 => Err(Error::from_raw_os_error(n * -1)),
            1 => Ok(ABI::V1),
            // Returns the greatest known ABI.
            _ => Ok(ABI::V1),
        }
    }
}

#[test]
fn abi_try_from() {
    assert_eq!(ABI::try_from(-38).unwrap_err().kind(), ErrorKind::Other);
    assert_eq!(
        ABI::try_from(-1).unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(ABI::try_from(0).unwrap_err().kind(), ErrorKind::Other);

    assert_eq!(ABI::try_from(1).unwrap(), ABI::V1);
    assert_eq!(ABI::try_from(2).unwrap(), ABI::V1);
    assert_eq!(ABI::try_from(9).unwrap(), ABI::V1);
}

/// Properly handles runtime unsupported features.  This enables to guarantee consistent behaviors
/// across crate users and runtime kernels even if this crate get new features.  It eases backward
/// compatibility and enables future-proofness.
///
/// Landlock is a security feature designed to help improve security of a running system thanks to
/// application developers.  To protect users as much as possible, compatibility with the running
/// system should then be handled in a best-effort way, contrary to common system features.  In
/// some circumstances (e.g. applications carefully designed to only be run with a specific kernel
/// version), it may be required to check if some of there features are enforced, which is possible
/// with the `Compat<T>::into_result()` helper.
pub struct Compat<T>(CompatObject<T>);

struct CompatObject<T> {
    /// Saves the last call status for `Compat<T>::into_result()`.
    last: LastCall,
    /// Saves the last encountered error for `RestrictionStatus`.
    // TODO: save the first error instead?
    prev_error: Option<Error>,
    compat: Compatibility,
    /// It is `None` if the build chain is incompatible with the running system.
    build: Option<CompatBuild<T>>,
}

impl<T> From<Compat<T>> for Option<CompatBuild<T>> {
    fn from(compat: Compat<T>) -> Self {
        compat.0.build
    }
}

/// Last attempted call, which may not be the last from the build chain.
enum LastCall {
    /// Did handle the build method and all arguments.
    FullSuccess,
    /// Did handle the build method but not all arguments (which had been made compatible for the
    /// call, e.g. removing some handled accesses).
    PartialSuccess,
    /// Didn't handle the build method or don't handle any argument.
    Unsupported,
    /// The build is None.
    Fake,
    /// Did handle the build method and a subset of arguments, but the call returned an error (e.g.
    /// invalid FD or not enough permissions).
    // This API should guarantee that no EINVAL is returned.
    RuntimeError(Error),
}

struct CompatBuild<T> {
    status: CompatStatus,
    data: T,
}

#[derive(Copy, Clone)]
enum CompatStatus {
    Full,
    Partial,
}

#[derive(Copy, Clone)]
pub enum ErrorThreshold {
    /// Handles the return value in a compatible way: method calls will always return `Ok(Self)`.
    /// This is the encouraged way to use this API.  The last runtime error in the build chain can
    /// be catched thanks to the return RestrictionStatus.
    NoError,
    /// Only considers a runtime error as an error.
    // Maps to LastCall::RuntimeError.
    Runtime,
    /// Considers a runtime error or a full incompatibility as an error.
    // Maps to LastCall::Unsupported.
    Incompatible,
    /// Considers a runtime error or a partial compatibility as an error.
    // Maps to LastCall::PartialSuccess.
    PartiallyCompatible,
}

impl From<CompatStatus> for LastCall {
    fn from(status: CompatStatus) -> Self {
        match status {
            CompatStatus::Full => LastCall::FullSuccess,
            CompatStatus::Partial => LastCall::PartialSuccess,
        }
    }
}

impl<T> Compat<T> {
    fn set_last_call_status(mut self, status: LastCall) -> Result<Self, Error> {
        // Only downgrades build compatibility.
        match status {
            LastCall::FullSuccess => {}
            _ => {
                if let Some(ref mut build) = self.0.build {
                    build.status = CompatStatus::Partial;
                }
            }
        }
        // Saves the previous error, if any.
        if let LastCall::RuntimeError(e) = replace(&mut self.0.last, status) {
            self.0.prev_error = Some(e);
        }
        self.into_result()
    }

    fn merge<U, V, F>(
        self,
        minimum_version: i32,
        other: Option<CompatBuild<V>>,
        new_data: F,
    ) -> Result<Compat<U>, Error>
    where
        F: FnOnce(T, V) -> Result<U, Error>,
    {
        let (status, build) = match (self.0.build, other) {
            (None, _) => (LastCall::Fake, None),
            (_, None) => (LastCall::Unsupported, None),
            (Some(self_build), Some(other_build)) => {
                if self.0.compat.is_compatible(minimum_version) {
                    match new_data(self_build.data, other_build.data) {
                        Ok(data) => (
                            other_build.status.into(),
                            Some(CompatBuild {
                                // Will be updated by the following call to set_last_call_status().
                                status: self_build.status,
                                data: data,
                            }),
                        ),
                        Err(e) => (LastCall::RuntimeError(e), None),
                    }
                } else {
                    (LastCall::Unsupported, None)
                }
            }
        };
        Compat(CompatObject {
            last: self.0.last,
            prev_error: self.0.prev_error,
            // TODO: Merge thresholds?
            compat: self.0.compat,
            build: build,
        })
        .set_last_call_status(status)
    }

    fn update<U, F>(self, minimum_version: i32, new_data: F) -> Result<Compat<U>, Error>
    where
        F: FnOnce(T) -> Result<U, Error>,
    {
        let other = Some(CompatBuild {
            status: CompatStatus::Full,
            data: 0,
        });
        // Artificial merge to factor out the update code.
        self.merge(minimum_version, other, |self_data, _| new_data(self_data))
    }

    fn into_result(self) -> Result<Self, Error> {
        match self.0.last {
            LastCall::FullSuccess => Ok(self),
            LastCall::PartialSuccess => match self.0.compat.threshold {
                ErrorThreshold::PartiallyCompatible => {
                    Err(Error::new(ErrorKind::InvalidData, "Partial compatibility"))
                }
                _ => Ok(self),
            },
            LastCall::Unsupported | LastCall::Fake => match self.0.compat.threshold {
                ErrorThreshold::PartiallyCompatible | ErrorThreshold::Incompatible => {
                    Err(Error::new(ErrorKind::InvalidData, "Incompatibility"))
                }
                _ => Ok(self),
            },
            // Matches ErrorThreshold::Runtime and all others.
            LastCall::RuntimeError(e) => Err(e),
        }
    }

    pub fn set_error_threshold(mut self, threshold: ErrorThreshold) -> Self {
        self.0.compat.threshold = threshold;
        self
    }
}

#[derive(Copy, Clone)]
pub struct Compatibility {
    abi: ABI,
    /// Saves the error threshold for the build chain.
    threshold: ErrorThreshold,
}

impl Compatibility {
    pub fn new() -> Result<Compatibility, Error> {
        Ok(Compatibility {
            abi: ABI::new_current()?,
            threshold: ErrorThreshold::NoError,
        })
    }

    pub fn set_error_threshold(&mut self, threshold: ErrorThreshold) {
        self.threshold = threshold;
    }

    fn is_compatible(&self, minimum_version: i32) -> bool {
        self.abi.is_compatible(minimum_version)
    }

    // @new_data returns a default fully supported version of an object.
    fn create<T, F>(&self, minimum_version: i32, new_data: F) -> Result<Compat<T>, Error>
    where
        F: FnOnce() -> T,
    {
        let is_compatible = self.is_compatible(minimum_version);
        Compat(CompatObject {
            last: LastCall::FullSuccess,
            prev_error: None,
            compat: *self,
            build: if is_compatible {
                Some(CompatBuild {
                    status: CompatStatus::Full,
                    data: new_data(),
                })
            } else {
                None
            },
        })
        .set_last_call_status(if is_compatible {
            LastCall::FullSuccess
        } else {
            LastCall::Unsupported
        })
    }
}

trait TryCompat {
    fn try_compat(self, compat: &Compatibility) -> Result<Self, Error>
    where
        Self: Sized;
}

impl<T> TryCompat for BitFlags<T>
where
    T: BitFlag,
    BitFlags<T>: From<ABI>,
{
    fn try_compat(self, compat: &Compatibility) -> Result<Self, Error> {
        if self.is_empty() {
            return Ok(self);
        }
        let compat_bits = self & Self::from(compat.abi);
        match compat.threshold {
            ErrorThreshold::NoError | ErrorThreshold::Runtime => Ok(compat_bits),
            ErrorThreshold::Incompatible => {
                if compat_bits.is_empty() {
                    Err(Error::new(ErrorKind::InvalidData, "Incompatible"))
                } else {
                    Ok(compat_bits)
                }
            }
            ErrorThreshold::PartiallyCompatible => {
                if self != compat_bits {
                    Err(Error::new(ErrorKind::InvalidData, "Incompatible"))
                } else {
                    Ok(compat_bits)
                }
            }
        }
    }
}

#[test]
fn compat_bit_flags() {
    let compat = Compatibility {
        abi: ABI::V1,
        threshold: ErrorThreshold::NoError,
    };
    let access_ro = make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir});
    assert_eq!(access_ro, access_ro.try_compat(&compat).unwrap());

    let access_empty = BitFlags::<AccessFs>::empty();
    assert_eq!(access_empty, access_empty.try_compat(&compat).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    fn ruleset_root_compat() -> Result<RestrictionStatus, Error> {
        let compat = Compatibility::new()?;
        RulesetInit::new(&compat)?
            .handle_fs(ABI::V1)?
            .create()?
            .set_no_new_privs(true)?
            .add_rule(PathBeneath::new(&compat, &File::open("/")?)?.allow_access(ABI::V1)?)?
            .restrict_self()
    }

    fn ruleset_root_fragile() -> Result<RestrictionStatus, Error> {
        let mut compat = Compatibility::new()?;
        // Sets default error threshold: abort the whole sandboxing for any runtime error.
        compat.set_error_threshold(ErrorThreshold::Runtime);
        RulesetInit::new(&compat)?
            // Must have at least the execute check…
            .set_error_threshold(ErrorThreshold::PartiallyCompatible)
            .handle_fs(AccessFs::Execute)?
            .set_error_threshold(ErrorThreshold::NoError)
            // …and possibly others.
            .handle_fs(ABI::V1)?
            .create()?
            .set_no_new_privs(true)?
            // Useful to catch wrong PathBeneath's FD type.
            .set_error_threshold(ErrorThreshold::Runtime)
            .add_rule(PathBeneath::new(&compat, &File::open("/")?)?.allow_access(ABI::V1)?)?
            .restrict_self()
    }

    #[test]
    fn allow_root_compat() {
        assert_eq!(
            ruleset_root_compat().unwrap(),
            RestrictionStatus::FullyRestricted
        );
    }

    #[test]
    fn allow_root_fragile() {
        assert_eq!(
            ruleset_root_fragile().unwrap(),
            RestrictionStatus::FullyRestricted
        );
    }
}

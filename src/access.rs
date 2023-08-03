use std::ops::{BitAnd, BitOr};

use crate::{
    AccessError, AddRuleError, AddRulesError, CompatError, CompatState, Compatibility,
    HandleAccessError, HandleAccessesError, Ruleset, TryCompat, ABI,
};

#[cfg(test)]
use crate::AccessFs;

pub trait Access: PrivateAccess {
    /// Gets the access rights defined by a specific [`ABI`].
    /// Union of [`from_read()`](Access::from_read) and [`from_write()`](Access::from_write).
    fn from_all(abi: ABI) -> Self {
        // An empty access-right would be an error if passed to the kernel, but because the kernel
        // doesn't support Landlock, no Landlock syscall should be called.  try_compat() should
        // also return RestrictionStatus::Unrestricted when called with unsupported/empty
        // access-righs.
        Self::from_read(abi) | Self::from_write(abi)
    }

    /// Gets the access rights identified as read-only according to a specific ABI.
    /// Exclusive with [`from_write()`](Access::from_write).
    fn from_read(abi: ABI) -> Self;

    /// Gets the access rights identified as write-only according to a specific ABI.
    /// Exclusive with [`from_read()`](Access::from_read).
    fn from_write(abi: ABI) -> Self;
}

pub trait PrivateAccess: Copy + Eq + BitOr<Output = Self> + BitAnd<Output = Self> {
    fn is_empty_flags(self) -> bool
    where
        Self: Access;

    fn all() -> Self
    where
        Self: Access;

    fn known_unknown_flags(self, all: Self) -> (Self, Self)
    where
        Self: Access;

    fn ruleset_handle_access(
        ruleset: &mut Ruleset,
        access: Self,
    ) -> Result<(), HandleAccessesError>
    where
        Self: Access;

    fn into_add_rules_error(error: AddRuleError<Self>) -> AddRulesError
    where
        Self: Access;

    fn into_handle_accesses_error(error: HandleAccessError<Self>) -> HandleAccessesError
    where
        Self: Access;
}

#[test]
fn bit_flags_full_negation() {
    let scoped_negation = !AccessFs::all();
    assert_eq!(scoped_negation, AccessFs::empty());
    // !BitFlags::<AccessFs>::all() could be equal to full_negation(BitFlags::<AccessFs>::all()))
    // if all the 64-bits would be used, which is not currently the case.
    assert_ne!(scoped_negation.bits(), !AccessFs::all().bits());
}

impl<T> TryCompat<T> for T
where
    T: Access,
{
    fn try_compat(self, compat: &mut Compatibility) -> Result<Self, CompatError<T>> {
        let (_known_flags, unknown_flags) = self.known_unknown_flags(Self::all());
        let (state, new_access) = if self.is_empty_flags() {
            // Empty access-rights would result to a runtime error.
            return Err(AccessError::Empty.into());
        } else if !unknown_flags.is_empty_flags() {
            // Unknown access-rights (at build time) would result to a runtime error.
            // This can only be reached by using the unsafe BitFlags::from_bits_unchecked().
            return Err(AccessError::Unknown {
                access: self,
                unknown: unknown_flags,
            }
            .into());
        } else {
            let (compatible_flags, incompatible_flags) =
                self.known_unknown_flags(T::from_all(compat.abi));
            if compatible_flags.is_empty_flags() {
                if compat.is_best_effort {
                    // TODO: This creates an empty access-right and could be an issue with
                    // future ABIs.  This method should return Result<Option<Self>,
                    // CompatError> instead, and in this case Ok(None).
                    (CompatState::No, compatible_flags)
                } else {
                    return Err(AccessError::Incompatible { access: self }.into());
                }
            } else if !incompatible_flags.is_empty_flags() {
                if compat.is_best_effort {
                    (CompatState::Partial, compatible_flags)
                } else {
                    return Err(AccessError::PartiallyCompatible {
                        access: self,
                        incompatible: incompatible_flags,
                    }
                    .into());
                }
            } else {
                (CompatState::Full, compatible_flags)
            }
        };
        compat.state.update(state);
        Ok(new_access)
    }
}

#[test]
fn compat_bit_flags() {
    use crate::ABI;

    let mut compat = ABI::V1.into();

    let ro_access = make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir});
    assert_eq!(ro_access, ro_access.try_compat(&mut compat).unwrap());

    let empty_access = AccessFs::empty();
    assert!(matches!(
        empty_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Empty)
    ));

    let all_unknown_access = unsafe { AccessFs::from_bits_unchecked(1 << 63) };
    assert!(matches!(
        all_unknown_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == all_unknown_access && unknown == all_unknown_access
    ));

    let some_unknown_access = unsafe { AccessFs::from_bits_unchecked(1 << 63 | 1) };
    assert!(matches!(
        some_unknown_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == some_unknown_access && unknown == all_unknown_access
    ));

    // Access-rights are valid (but ignored) when they are not required for the current ABI.
    compat.abi = ABI::Unsupported;
    assert_eq!(empty_access, ro_access.try_compat(&mut compat).unwrap());

    // Access-rights are not valid when they are required for the current ABI.
    compat.is_best_effort = false;
    assert!(matches!(
        ro_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Incompatible { access }) if access == ro_access
    ));
}

// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    private, AccessError, AddRuleError, AddRulesError, BitFlags, CompatError, CompatResult,
    Compatibility, HandleAccessError, HandleAccessesError, Ruleset, RulesetCreated,
    TailoredCompatLevel, TryCompat, ABI,
};
use enumflags2::BitFlag;
use std::marker::PhantomData;

#[cfg(test)]
use crate::{make_bitflags, AccessFs, CompatLevel, CompatState};

pub trait Access: BitFlag + private::Sealed {
    /// Gets the access rights defined by a specific [`ABI`].
    fn from_all(abi: ABI) -> BitFlags<Self>;
}

// This HandledAccess trait is useful to document the API.
pub trait HandledAccess: Access {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Requested {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Effective {}

/// Requested or ABI-resolved ruleset attribute masks for one
/// [`Access`] category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RulesetMasks<A, S>
where
    A: Access,
{
    /// The handled access mask, or the scoped mask when `A` is
    /// [`Scope`](crate::Scope).
    pub(crate) access: BitFlags<A>,
    pub(crate) quiet: BitFlags<A>,
    _state: PhantomData<S>,
}

impl<A> Default for RulesetMasks<A, Requested>
where
    A: Access,
{
    fn default() -> Self {
        // Ruleset masks must start empty independently of BitFlags' customizable default.
        Self {
            access: BitFlags::EMPTY,
            quiet: BitFlags::EMPTY,
            _state: PhantomData,
        }
    }
}

impl<A> RulesetMasks<A, Requested>
where
    A: Access,
{
    const QUIET_SINCE: ABI = ABI::V10;

    pub(crate) fn supports_quiet(abi: ABI) -> bool {
        abi >= Self::QUIET_SINCE
    }

    pub(crate) fn request(
        &mut self,
        access: BitFlags<A>,
        compat: &mut Compatibility,
    ) -> Result<(), CompatError<A>> {
        self.access |= access;
        // Keep this call for validation, compatibility-state transitions, and errors.
        // Its filtered mask is redundant: resolve() derives it from the ruleset mask and ABI.
        let _ = access.try_compat(compat.abi(), compat.level, &mut compat.state)?;
        Ok(())
    }

    pub(crate) fn request_quiet(
        &mut self,
        access: BitFlags<A>,
        compat: &mut Compatibility,
    ) -> Result<(), CompatError<A>> {
        self.quiet |= access;
        // Keep both checks for their compatibility-state transitions and errors.
        let _ = access.try_compat(compat.abi(), compat.level, &mut compat.state)?;
        let _ = compat.try_compat_binary(Self::supports_quiet(compat.abi()), || {
            CompatError::<A>::QuietNotSupported
        })?;
        Ok(())
    }

    pub(crate) fn resolve(self, abi: ABI) -> RulesetMasks<A, Effective> {
        let effective_access = self.access & A::from_all(abi);
        RulesetMasks {
            access: effective_access,
            quiet: if Self::supports_quiet(abi) {
                self.quiet & effective_access
            } else {
                BitFlags::EMPTY
            },
            _state: PhantomData,
        }
    }

    pub(crate) fn incompatible_quiet(self) -> BitFlags<A> {
        self.quiet & !self.access
    }
}

#[test]
fn ruleset_masks_resolve() {
    let supports_quiet = RulesetMasks::<AccessFs, Requested>::supports_quiet;
    assert!(!supports_quiet(ABI::V9));
    assert!(supports_quiet(ABI::V10));

    let requested_masks = RulesetMasks::<_, Requested> {
        access: make_bitflags!(AccessFs::{Execute | Refer}),
        quiet: AccessFs::Execute.into(),
        _state: PhantomData,
    };
    for (abi, expected_access, expected_quiet) in [
        (ABI::Unsupported, BitFlags::EMPTY, BitFlags::EMPTY),
        (ABI::V1, AccessFs::Execute.into(), BitFlags::EMPTY),
        (
            ABI::V2,
            make_bitflags!(AccessFs::{Execute | Refer}),
            BitFlags::EMPTY,
        ),
        (
            ABI::V9,
            make_bitflags!(AccessFs::{Execute | Refer}),
            BitFlags::EMPTY,
        ),
        (
            ABI::V10,
            make_bitflags!(AccessFs::{Execute | Refer}),
            AccessFs::Execute.into(),
        ),
    ] {
        assert_eq!(
            requested_masks.resolve(abi),
            RulesetMasks::<_, Effective> {
                access: expected_access,
                quiet: expected_quiet,
                _state: PhantomData,
            }
        );
    }
}

pub trait PrivateHandledAccess: HandledAccess {
    fn ruleset_handle_access(
        ruleset: &mut Ruleset,
        access: BitFlags<Self>,
    ) -> Result<(), HandleAccessesError>
    where
        Self: Access;

    fn ruleset_quiet_access(
        ruleset: &mut Ruleset,
        access: BitFlags<Self>,
    ) -> Result<(), HandleAccessesError>
    where
        Self: Access;

    fn ruleset_has_effective_quiet_access(ruleset: &RulesetCreated, abi: ABI) -> bool;

    fn into_add_rules_error(error: AddRuleError<Self>) -> AddRulesError
    where
        Self: Access;

    fn into_handle_accesses_error(error: HandleAccessError<Self>) -> HandleAccessesError
    where
        Self: Access;
}

// Creates an illegal/overflowed BitFlags<T> with all its bits toggled, including undefined ones.
fn full_negation<T>(flags: BitFlags<T>) -> BitFlags<T>
where
    T: Access,
{
    unsafe { BitFlags::<T>::from_bits_unchecked(!flags.bits()) }
}

#[test]
fn bit_flags_full_negation() {
    let scoped_negation = !BitFlags::<AccessFs>::all();
    assert_eq!(scoped_negation, BitFlags::<AccessFs>::empty());
    // !BitFlags::<AccessFs>::all() could be equal to full_negation(BitFlags::<AccessFs>::all()))
    // if all the 64-bits would be used, which is not currently the case.
    assert_ne!(scoped_negation, full_negation(BitFlags::<AccessFs>::all()));
}

impl<A> TailoredCompatLevel for BitFlags<A> where A: Access {}

impl<A> TryCompat<A> for BitFlags<A>
where
    A: Access,
{
    fn try_compat_inner(&mut self, abi: ABI) -> Result<CompatResult<A>, CompatError<A>> {
        if self.is_empty() {
            // Empty access-rights would result to a runtime error.
            Err(AccessError::Empty.into())
        } else if !Self::all().contains(*self) {
            // Unknown access-rights (at build time) would result to a runtime error.
            // This can only be reached by using the unsafe BitFlags::from_bits_unchecked().
            Err(AccessError::Unknown {
                access: *self,
                unknown: *self & full_negation(Self::all()),
            }
            .into())
        } else {
            let compat = *self & A::from_all(abi);
            let ret = if compat.is_empty() {
                Ok(CompatResult::No(
                    AccessError::Incompatible { access: *self }.into(),
                ))
            } else if compat != *self {
                let error = AccessError::PartiallyCompatible {
                    access: *self,
                    incompatible: *self & full_negation(compat),
                }
                .into();
                Ok(CompatResult::Partial(error))
            } else {
                Ok(CompatResult::Full)
            };
            *self = compat;
            ret
        }
    }
}

#[test]
fn compat_bit_flags() {
    use crate::ABI;

    let mut compat: Compatibility = ABI::V1.into();
    assert!(compat.state == CompatState::Init);

    let ro_access = make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir});
    assert_eq!(
        ro_access,
        ro_access
            .try_compat(compat.abi(), compat.level, &mut compat.state)
            .unwrap()
            .unwrap()
    );
    assert!(compat.state == CompatState::Full);

    let empty_access = BitFlags::<AccessFs>::empty();
    assert!(matches!(
        empty_access
            .try_compat(compat.abi(), compat.level, &mut compat.state)
            .unwrap_err(),
        CompatError::Access(AccessError::Empty)
    ));

    let all_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked(1 << 63) };
    assert!(matches!(
        all_unknown_access.try_compat(compat.abi(), compat.level, &mut compat.state).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == all_unknown_access && unknown == all_unknown_access
    ));
    // An error makes the state final.
    assert!(compat.state == CompatState::Dummy);

    let some_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked((1 << 63) | 1) };
    assert!(matches!(
        some_unknown_access.try_compat(compat.abi(), compat.level, &mut compat.state).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == some_unknown_access && unknown == all_unknown_access
    ));
    assert!(compat.state == CompatState::Dummy);

    compat = ABI::Unsupported.into();

    // Tests that the ruleset is marked as unsupported.
    assert!(compat.state == CompatState::Init);

    // Access-rights are valid (but ignored) when they are not required for the current ABI.
    assert_eq!(
        None,
        ro_access
            .try_compat(compat.abi(), compat.level, &mut compat.state)
            .unwrap()
    );

    assert!(compat.state == CompatState::No);

    // Access-rights are not valid when they are required for the current ABI.
    compat.level = Some(CompatLevel::HardRequirement);
    assert!(matches!(
        ro_access.try_compat(compat.abi(), compat.level, &mut compat.state).unwrap_err(),
        CompatError::Access(AccessError::Incompatible { access }) if access == ro_access
    ));

    compat = ABI::V1.into();

    // Tests that the ruleset is marked as the unknown compatibility state.
    assert!(compat.state == CompatState::Init);

    // Access-rights are valid (but ignored) when they are not required for the current ABI.
    assert_eq!(
        ro_access,
        ro_access
            .try_compat(compat.abi(), compat.level, &mut compat.state)
            .unwrap()
            .unwrap()
    );

    // Tests that the ruleset is in an unsupported state, which is important to be able to still
    // enforce no_new_privs.
    assert!(compat.state == CompatState::Full);

    let v2_access = ro_access | AccessFs::Refer;

    // Access-rights are not valid when they are required for the current ABI.
    compat.level = Some(CompatLevel::HardRequirement);
    assert!(matches!(
        v2_access.try_compat(compat.abi(), compat.level, &mut compat.state).unwrap_err(),
        CompatError::Access(AccessError::PartiallyCompatible { access, incompatible })
            if access == v2_access && incompatible == AccessFs::Refer
    ));
}

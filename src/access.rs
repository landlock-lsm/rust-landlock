use std::ops::{BitAnd, BitOr, Not};

use crate::{
    AccessError, AddRuleError, AddRulesError, CompatError, CompatResult, HandleAccessError,
    HandleAccessesError, Ruleset, TailoredCompatLevel, TryCompat, ABI,
};

#[cfg(test)]
use crate::{AccessFs, CompatLevel, CompatState, Compatibility};

pub trait Access: PrivateAccess + TailoredCompatLevel {
    /// Gets the access rights defined by a specific [`ABI`].
    fn from_all(abi: ABI) -> Self;
}

pub trait PrivateAccess:
    core::fmt::Debug + Copy + BitOr<Output = Self> + BitAnd<Output = Self> + Not<Output = Self>
{
    fn is_empty(self) -> bool
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
fn bit_flags_negation() {
    let scoped_negation = !AccessFs::all();
    assert_eq!(scoped_negation, AccessFs::EMPTY);
}

impl<A> TryCompat<A> for A
where
    A: Access,
{
    fn try_compat_inner(&mut self, abi: ABI) -> Result<CompatResult<A>, CompatError<A>> {
        if self.is_empty() {
            // Empty access-rights would result to a runtime error.
            Err(AccessError::Empty.into())
        } else {
            let compat = *self & A::from_all(abi);
            let incompatible_flags = *self & !A::from_all(abi);
            let ret = if compat.is_empty() {
                Ok(CompatResult::No(
                    AccessError::Incompatible { access: *self }.into(),
                ))
            } else if !incompatible_flags.is_empty() {
                let error = AccessError::PartiallyCompatible {
                    access: *self,
                    incompatible: incompatible_flags,
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

    let empty_access = AccessFs::EMPTY;
    assert!(matches!(
        empty_access
            .try_compat(compat.abi(), compat.level, &mut compat.state)
            .unwrap_err(),
        CompatError::Access(AccessError::Empty)
    ));

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

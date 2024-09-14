use std::ops::{BitAnd, BitOr, Not};

use crate::{
    AccessError, AddRuleError, AddRulesError, CompatError, CompatResult, HandleAccessError,
    HandleAccessesError, Ruleset, TailoredCompatLevel, TryCompat, ABI,
};

#[cfg(test)]
use crate::{AccessFs, CompatLevel, CompatState, Compatibility};

#[macro_export]
macro_rules! make_bitflags {
    ($bitflag_type:ident :: {$($flag:ident)|*}) => {
        $bitflag_type::EMPTY $(.union($bitflag_type::$flag))*
    };
}

macro_rules! bitflags_type {
    (
        $(#[$bitflags_attr:meta])*
        $vis:vis struct $bitflags_name:ident: $bitflags_type:ty {
            $(
                $(#[$flag_attr:meta])*
                const $flag_name:ident = $flag_val:expr;
            )*
        }
    ) => {
        $(#[$bitflags_attr])*
        #[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
        $vis struct $bitflags_name($bitflags_type);

        impl $bitflags_name {
            $(
                #[allow(non_upper_case_globals)]
                $(#[$flag_attr])*
                $vis const $flag_name: Self = Self($flag_val);
            )*

            $vis const EMPTY: Self = Self(0);

            $vis const fn is_empty(&self) -> bool {
                self.0 == 0
            }

            $vis const fn union(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }

            $vis const fn contains(self, rhs: Self) -> bool {
                self.0 & rhs.0 == rhs.0
            }

            pub(crate) const fn all() -> Self {
                Self(0 $(| $flag_val)*)
            }

            pub(crate) const fn bits(self) -> $bitflags_type {
                self.0
            }
        }

        impl core::ops::BitAnd for $bitflags_name {
            type Output = Self;

            fn bitand(self, rhs: Self) -> Self {
                Self(self.0 & rhs.0)
            }
        }

        impl core::ops::BitAndAssign for $bitflags_name {
            fn bitand_assign(&mut self, rhs: Self) {
                self.0 &= rhs.0;
            }
        }

        impl core::ops::BitOr for $bitflags_name {
            type Output = Self;

            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $bitflags_name {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl core::ops::BitXor for $bitflags_name {
            type Output = Self;

            fn bitxor(self, rhs: Self) -> Self {
                Self(self.0 ^ rhs.0)
            }
        }

        impl core::ops::BitXorAssign for $bitflags_name {
            fn bitxor_assign(&mut self, rhs: Self) {
                self.0 ^= rhs.0;
            }
        }

        impl core::ops::Not for $bitflags_name {
            type Output = Self;

            fn not(self) -> Self {
                Self(!self.0) & Self::all()
            }
        }
    };
}
pub(crate) use bitflags_type;

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
fn bit_flags_full_negation() {
    let scoped_negation = !AccessFs::all();
    assert_eq!(scoped_negation, AccessFs::EMPTY);
    // !AccessFs::all() could be equal to !AccessFs::all().bits() if
    // all the 64-bits would be used, which is not currently the case.
    assert_ne!(scoped_negation.bits(), !AccessFs::all().bits());
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

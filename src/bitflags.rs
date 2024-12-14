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
        #[derive(Copy, Clone, PartialEq, Eq, Default)]
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

        impl core::fmt::Debug for $bitflags_name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                const VARIANTS: &[($bitflags_name, &str)] = &[
                    $(($bitflags_name::$flag_name, stringify!($flag_name)),)*
                ];

                write!(f, concat!(stringify!($bitflags_name), "("))?;
                let mut first = true;
                for &(val, name) in VARIANTS {
                    if self.contains(val) {
                        if !first {
                            write!(f, " | ")?;
                        }
                        first = false;
                        write!(f, "{name}")?;
                    }
                }
                write!(f, ")")
            }
        }
    };
}
pub(crate) use bitflags_type;

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    super::bitflags_type! {
        pub struct AccessFs: u64 {
            const Execute = 1;
            const WriteFile = 2;
            const ReadFile = 4;
        }
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", AccessFs::EMPTY), "AccessFs()");
        assert_eq!(
            format!("{:?}", AccessFs::all()),
            "AccessFs(Execute | WriteFile | ReadFile)"
        );
        assert_eq!(format!("{:?}", AccessFs::WriteFile), "AccessFs(WriteFile)");
    }
}

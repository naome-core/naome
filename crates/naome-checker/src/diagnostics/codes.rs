//! Numeric identifiers for checker diagnostics and their structured details.

macro_rules! diagnostic_units {
    (
        $(#[$meta:meta])* $name:ident, $catalog:ident, $label:literal, $domain:literal {
            $( $variant:ident = $id:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u32)]
        pub enum $name {
            $( $variant = ($domain << 16) | $id, )+
        }
        impl $name {
            /// Stable machine code of this value.
            pub fn code(self) -> u32 { self as u32 }
        }
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_u32(self.code())
            }
        }
        /// Assigned diagnostic values for the machine catalog.
        pub const $catalog: &[(&str, &str, u32)] = &[
            $( ($label, stringify!($variant), $name::$variant as u32), )+
        ];
    };
}

// One table owns each diagnostic code, typed fields and catalog entry.
macro_rules! diagnostic_codes {
    (
        $(#[$meta:meta])* $name:ident, $catalog:ident, $label:literal,
        structured { $( $variant:ident = $code:literal { $( $field:ident: $ty:ty ),+ $(,)? } ),+ $(,)? }
        units { $( $unit:ident = $unit_code:literal ),* $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum $name {
            $( $variant { $( $field: $ty ),+ }, )+
            $( $unit, )*
        }
        impl $name {
            /// Stable machine code of this condition.
            pub fn code(&self) -> u32 {
                match self {
                    $( Self::$variant { .. } => $code, )+
                    $( Self::$unit => $unit_code, )*
                }
            }
        }
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeStruct;
                match self {
                    $( Self::$variant { $( $field ),+ } => {
                        let mut value = serializer.serialize_struct(stringify!($name), 1 $(+ { let _ = stringify!($field); 1 })+)?;
                        value.serialize_field("code", &$code)?;
                        $( value.serialize_field(stringify!($field), $field)?; )+
                        value.end()
                    }, )+
                    $( Self::$unit => {
                        let mut value = serializer.serialize_struct(stringify!($name), 1)?;
                        value.serialize_field("code", &$unit_code)?;
                        value.end()
                    }, )*
                }
            }
        }
        /// Assigned diagnostic codes for the machine catalog.
        pub const $catalog: &[(&str, &str, u32)] = &[
            $( ($label, stringify!($variant), $code), )+
            $( ($label, stringify!($unit), $unit_code), )*
        ];
    };
}

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

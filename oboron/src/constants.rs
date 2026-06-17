// Fixed key for oboron (testing only - NOT SECURE)
// Master value
#[doc(hidden)]
pub const HARDCODED_KEY_BYTES: [u8; 64] = [
    0x38, 0x12, 0x84, 0x63, 0x3d, 0x02, 0xea, 0x5f, 0x35, 0xdf, 0x85, 0x96, 0xb5, 0xcc, 0x42, 0x18,
    0x31, 0x00, 0x60, 0x46, 0x8e, 0x8b, 0x46, 0x54, 0x55, 0xa4, 0x15, 0x17, 0x4e, 0xa6, 0xe9, 0x66,
    0xa9, 0xf4, 0x8e, 0xec, 0x4b, 0xa4, 0x46, 0xdd, 0xfc, 0x8b, 0x78, 0x58, 0x78, 0x95, 0x35, 0x6f,
    0x45, 0xa7, 0x5a, 0x1a, 0xb7, 0x41, 0x94, 0x54, 0xdd, 0x9f, 0x7a, 0xa8, 0xa9, 0x5d, 0xbd, 0xd5,
];

#[doc(hidden)]
pub const HARDCODED_KEY_HEX: &str =
    "38128463\
3d02ea5f\
35df8596\
b5cc4218\
31006046\
8e8b4654\
55a41517\
4ea6e966\
a9f48eec\
4ba446dd\
fc8b7858\
7895356f\
45a75a1a\
b7419454\
dd9f7aa8\
a95dbdd5";

// Format identifiers
//
#[cfg(feature = "dgcmsiv")]
pub(crate) mod dgcmsiv_constants {
    pub const DGCMSIV_C32_STR: &str = "dgcmsiv.c32";
    pub const DGCMSIV_B32_STR: &str = "dgcmsiv.b32";
    pub const DGCMSIV_B64_STR: &str = "dgcmsiv.b64";
    pub const DGCMSIV_HEX_STR: &str = "dgcmsiv.hex";
}

#[cfg(feature = "pgcmsiv")]
pub(crate) mod pgcmsiv_constants {
    pub const PGCMSIV_C32_STR: &str = "pgcmsiv.c32";
    pub const PGCMSIV_B32_STR: &str = "pgcmsiv.b32";
    pub const PGCMSIV_B64_STR: &str = "pgcmsiv.b64";
    pub const PGCMSIV_HEX_STR: &str = "pgcmsiv.hex";
}

#[cfg(feature = "dsiv")]
pub(crate) mod dsiv_constants {
    pub const DSIV_C32_STR: &str = "dsiv.c32";
    pub const DSIV_B32_STR: &str = "dsiv.b32";
    pub const DSIV_B64_STR: &str = "dsiv.b64";
    pub const DSIV_HEX_STR: &str = "dsiv.hex";
}

#[cfg(feature = "psiv")]
pub(crate) mod psiv_constants {
    pub const PSIV_C32_STR: &str = "psiv.c32";
    pub const PSIV_B32_STR: &str = "psiv.b32";
    pub const PSIV_B64_STR: &str = "psiv.b64";
    pub const PSIV_HEX_STR: &str = "psiv.hex";
}

#[cfg(feature = "mock")]
pub(crate) mod mock_constants {
    pub const MOCK1_B32_STR: &str = "mock1.b32";
    pub const MOCK1_B64_STR: &str = "mock1.b64";
    pub const MOCK1_C32_STR: &str = "mock1.c32";
    pub const MOCK1_HEX_STR: &str = "mock1.hex";
    pub const MOCK2_B32_STR: &str = "mock2.b32";
    pub const MOCK2_B64_STR: &str = "mock2.b64";
    pub const MOCK2_C32_STR: &str = "mock2.c32";
    pub const MOCK2_HEX_STR: &str = "mock2.hex";
}

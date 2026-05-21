// AES-CBC padding byte
#[cfg(any(feature = "zrbcx"))]
pub const CBC_PADDING_BYTE: u8 = 0x01;
#[cfg(any(feature = "legacy", feature = "zrbcx"))]
pub const AES_BLOCK_SIZE: usize = 16;

pub enum Endianness {
    BigEndian,
    LittleEndian,
}

pub fn lsb_to_msb(bytes : &[u8]) -> Vec<u8> {
    let mut ret = bytes.to_vec();

    ret.reverse();
    ret
}

pub fn slice_to_u16(bytes : &[u8], endianness : Endianness) -> u16 {
    match endianness {
        Endianness::BigEndian => (bytes[0] as u16) << 8 | (bytes[1] as u16),
        Endianness::LittleEndian => (bytes[0] as u16) | (bytes[1] as u16) << 8,
    }
}

pub fn slice_to_u32(bytes : &[u8], endianness : Endianness) -> u32 {
    match endianness {
        Endianness::BigEndian => (bytes[0] as u32) << 24 |
                                 (bytes[1] as u32) << 16 |
                                 (bytes[2] as u32) << 8 |
                                 (bytes[3] as u32),
        Endianness::LittleEndian => (bytes[0] as u32) |
                                    (bytes[1] as u32) << 8 |
                                    (bytes[2] as u32) << 16 |
                                    (bytes[3] as u32) << 24,
    }
}

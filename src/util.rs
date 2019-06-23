
pub fn print_bytes(bytes: &Vec<u8>) {
    let width: usize = 16;

    for chunk in bytes.chunks(width) {
        for i in 0..chunk.len() {
            match i % 2 {
                0 => print!("{:02x}", chunk[i]),
                _ => print!("{:02x} ", chunk[i]),
            };
        }

        if chunk.len() < width {
            let difference = width - chunk.len();
            print!("{:1$}", "", 2 * difference + difference / 2 + 1);
        }

        print!("\t");
        for byte in chunk {
            match byte.is_ascii_alphanumeric() {
                true => print!("{}", *byte as char),
                false => print!("."),
            };
        }
        print!("\n");
    }
    print!("\n");
}

/** Converts a slice of 4 bytes into an u32. Assumes slice is big endian. */
pub fn bytes_to_u32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 24) |
    ((bytes[1] as u32) << 16) |
    ((bytes[2] as u32) << 8) |
    bytes[3] as u32
}

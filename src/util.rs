
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

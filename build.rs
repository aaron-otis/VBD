extern crate bindgen;

use std::env;
use std::path::PathBuf;
use bindgen::Builder;

fn main() {
    for lib in ["bfd", "capstone"].iter() {
        println!("cargo:rustc-link-lib={}", lib);

        let header = format!("{}_wrapper.h", lib);
        let bindings = Builder::default().header(header).generate()
                                         .expect("Unable to generate bindings");
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        let fname = format!("bgen_{}.rs", lib);

        bindings.write_to_file(out_path.join(fname))
                .expect("Couldn't write bindings");
    }
}

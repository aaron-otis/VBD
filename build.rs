extern crate bindgen;

use std::env;
use std::path::PathBuf;
use bindgen::{builder, Builder};

fn main() {
    // C libraries.
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

    // C++ libraries.
    /* FIXME: This doesn't work and might not ever...
    println!("cargo:rustc-link-lib=dyninstAPI");
    println!("cargo:rustc-link-lib=common");
    println!("cargo:rustc-link-lib=boost_system");

    let header = "dyninst_wrapper.h";
    let bindings = builder().header(header)
                            .clang_arg("-x c++")
                            .clang_arg("-lstdc++")
                            .clang_arg("-std=c++14")
                            //.clang_arg("")
                            .generate()
                            .expect("Unable to open dyninst bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let fname = "bgen_dyninst.rs";

    bindings.write_to_file(out_path.join(fname))
            .expect("Couldn't write dyninst bindings");
    */
}

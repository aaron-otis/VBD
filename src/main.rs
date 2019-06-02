extern crate argparse;
extern crate p8n_types;

pub mod binary;
pub mod conversions;
pub mod bfd;
pub mod bgen_bfd;
pub mod capstone;
pub mod util;
pub mod statistics;
pub mod graphs;

use binary::binary::Binary;
use statistics::{count_instructions, print_statistics};
//use binary::section::{print_sections, print_section_contents};
//use binary::symbol::{print_symbols};
use argparse::{ArgumentParser, StoreTrue, Store};
use std::{env, process};

struct Options {
    fname: String,
    sections: bool,
    dump_sec: bool,
    symbols: bool,
    disam: bool,
    stats: bool,
    all: bool,
}

fn main() {
    // Set default options.
    let mut options = Options {
        fname: String::new(),
        sections: false,
        dump_sec: false,
        symbols: false,
        disam: false,
        stats: false,
        all: false,
    };

    // Set argparse options.
    {
        let mut ap = ArgumentParser::new();

        ap.set_description("Binary analysis tool");
        ap.refer(&mut options.fname)
          .add_argument("file name", Store, "File to analyze");
        ap.refer(&mut options.sections)
          .add_option(&["-S", "--sections"],
                      StoreTrue,
                      "Display information in the file's section headers.");
        ap.refer(&mut options.symbols)
          .add_option(&["-s", "--symbols"],
                      StoreTrue,
                      "Display entries in the symbols table.");
        ap.refer(&mut options.dump_sec)
          .add_option(&["-C", "--section-contents"],
                      StoreTrue,
                      "Display the contents of each section in hexadecimal format.");
        ap.refer(&mut options.disam)
          .add_option(&["-d", "--disassemble"],
                      StoreTrue,
                      "Disassemble the text section of the program.");
        ap.refer(&mut options.stats)
          .add_option(&["-T", "--satistics"],
                      StoreTrue,
                      "Gather statistics on the given binary.");
        ap.refer(&mut options.all).add_option(&["-A", "--all"],
                                              StoreTrue, "Enable all options");
        ap.parse_args_or_exit();

    }

    if options.fname.is_empty() {
        let args: Vec<String> = env::args().collect();
        println!("Usage: {} [OPTIONS] [FILE NAME]", args[0]);
        process::exit(1);
    }

    // Parse binary.
    let mut b = match Binary::new(options.fname) {
        Ok(b) => b,
        Err(_e) => panic!("unable to load binary"),
    };

    println!("File:\t{}\nType:\t{}\nArch:\t{}\nEntry:\t0x{:016x}\n",
               b.filename, b.type_str, b.arch_str, b.entry);
    if options.all {
        options.sections = true;
        options.symbols = true;
        options.dump_sec = true;
        options.disam = true;
    }
    if options.sections {
        b.print_sections();
    }
    if options.symbols {
        //print_symbols(&b.symbols);
        b.print_symbols();
    }
    if options.dump_sec {
        println!("Section contents:");
        b.print_section_contents();
        print!("\n");
    }
    if options.disam {
        match b.disassemble() {
            Ok(_) => {
                for block in b.blocks.clone() {
                    println!("{}\n", block);
                }
                match b.cfg() {
                    Some(cfg) => {
                        for edge in cfg.edges {
                            print!("{}, ", edge);
                        }
                        println!("");
                    },
                    None => (),
                };
                println!("Successfully disassembled binary")
            },
            Err(e) => println!("Error disassembling: {}", e),
        };
    }
    if options.stats {
        // FIXME: Don't potentially disassemble twice.
        match b.disassemble() {
            Ok(_) => print_statistics(&count_instructions(&b)),
            Err(e) => println!("Error disassembling: {}", e),
        };
    }
}

extern crate argparse;
extern crate regex;

pub mod binary;
pub mod conversions;
pub mod bfd;
pub mod bgen_bfd;
pub mod capstone;
pub mod util;
pub mod statistics;
pub mod graphs;
pub mod sample;

use binary::binary::Binary;
use statistics::{count_instructions, print_statistics};
use argparse::{ArgumentParser, StoreTrue, Store};
use std::{env, process};
use sample::Sample;

struct Options {
    fname: String,
    sections: bool,
    dump_sec: bool,
    symbols: bool,
    disam: bool,
    stats: bool,
    loops: bool,
    analysis: bool,
    all: bool,
}

fn main() {
    // Set default options.
    let mut options: Options = Options {
        fname: String::new(),
        sections: false,
        dump_sec: false,
        symbols: false,
        disam: false,
        stats: false,
        loops: false,
        analysis: false,
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
        ap.refer(&mut options.loops)
          .add_option(&["-l", "--loops"],
                      StoreTrue,
                      "Print the number of loops detected in the binary.");
        ap.refer(&mut options.analysis)
          .add_option(&["--analyze"],
                      StoreTrue,
                      "Analyze the given binary for potential ransomware signs.");
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
    let mut b: Binary = match Binary::new(options.fname) {
        Ok(bin) => bin,
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

    // Disassemble the binary if any of these options are selected.
    if options.disam || options.stats || options.loops {
        match b.disassemble() {
            Ok(_) => {
                println!("Successfully disassembled binary")
            },
            Err(e) => println!("Error disassembling: {}", e),
        };
    }
    if options.disam {
        for block in b.blocks.clone() {
            println!("{}\n", block);
        }
    }
    if options.stats {
        print_statistics(&count_instructions(&b));
    }
    if options.loops {
        println!("Detected {} loops", b.detect_loops().len());
    }
    if options.analysis {
        let mut sample: Sample = Sample::new(b);
        sample.analysis();
        statistics::print_statistics(&sample.counts);
        println!("Detected {} loops", sample.loops);
        println!("Detected {} bitwise arithmetic operations", sample.bitops);
        println!("Detected {} cryptographic constants", sample.constants.len());
        println!("Detected {} strings that are commonly seen in ransom notes",
                 sample.strings.len());
    }
}

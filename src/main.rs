extern crate argparse;
extern crate regex;

#[macro_use]
extern crate lazy_static;

#[macro_use(bson, doc)]
extern crate mongodb;

pub mod binary;
pub mod conversions;
pub mod bfd;
pub mod bgen_bfd;
pub mod capstone;
pub mod util;
pub mod statistics;
pub mod graphs;
pub mod sample;

use argparse::{ArgumentParser, StoreTrue, Store};
use binary::binary::Binary;
use mongodb::{Client, ThreadedClient};
use mongodb::db::ThreadedDatabase;
use mongodb::coll::Collection;
use sample::Sample;
use statistics::{count_instructions, print_statistics};
use std::{env, fmt, process};
use std::time::{Duration, Instant};

enum Error {
    BinaryError,
    DisassemblyError,
}

enum Platform {
    Unix,
    Linux,
    Windows,
    Unknown,
}

struct Options {
    fname: String,
    sections: bool,
    dump_sec: bool,
    symbols: bool,
    disam: bool,
    stats: bool,
    loops: bool,
    analysis: bool,
    server: String,
    port: u16,
    dbname: String,
    verbose: bool,
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
        server: "localhost".to_string(),
        port: 27017,
        dbname: "statistics".to_string(),
        verbose: false,
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
        ap.refer(&mut options.server)
          .add_option(&["--server"],
                      Store,
                      "The MongoDB server to connect to (default: localhost).");
        ap.refer(&mut options.port)
          .add_option(&["--port"],
                      Store,
                      "The port of the MongoDB server to connect to (default: 27017).");
        ap.refer(&mut options.dbname)
          .add_option(&["--database"],
                      Store,
                      "The name of the MongoDB database to use (default: statistics).");
        ap.refer(&mut options.verbose)
          .add_option(&["-v", "--verbose"],
                      StoreTrue,
                      "Be verbose.");
        ap.refer(&mut options.all).add_option(&["-A", "--all"],
                                              StoreTrue, "Enable all options");
        ap.parse_args_or_exit();

    }

    if options.fname.is_empty() {
        let args: Vec<String> = env::args().collect();
        println!("Usage: {} [OPTIONS] [FILE NAME]", args[0]);
        process::exit(1);
    }

    if options.all {
        options.sections = true;
        options.symbols = true;
        options.dump_sec = true;
        options.disam = true;
    }

    // Connect to database.
    let client = match Client::connect(&options.server, options.port) {
        Ok(client) => client,
        Err(e) => panic!("Database connection failed: {}", e)
    };

    let platform: Platform;
    if cfg!(linux) {
        platform = Platform::Linux;
    }
    else if cfg!(unix) {
        platform = Platform::Unix;
    }
    else if cfg!(windows) {
        platform = Platform::Windows;
    }
    else {
        platform = Platform::Unknown;
    }
    let collection = client.db(&options.dbname).collection(&platform.to_string());

    match analyze_binary(&options, collection) {
        Ok(_) => (),
        Err(e) => println!("Failed to analyze '{}': {}", options.fname, e)
    };
}

fn analyze_binary(options: &Options, collection: Collection) -> Result<(), Error> {
    let now = Instant::now();
    let mut b: Binary = match Binary::new(options.fname.clone()) {
        Ok(bin) => bin,
        Err(_e) => return Err(Error::BinaryError)
    };

    println!("File:\t{}\nType:\t{}\nArch:\t{}\nEntry:\t0x{:016x}\n",
             b.filename,
             b.type_str,
             b.arch_str,
             b.entry);

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
            Ok(_) => if options.verbose {
                println!("Successfully disassembled binary")
            },
            Err(e) => {
                println!("Error disassembling: {}", e);
                return Err(Error::DisassemblyError);
            },
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

        let time = now.elapsed();
        if options.verbose {
            statistics::print_statistics(&sample.counts);
            println!("Detected {} loops", sample.loops);
            println!("Detected {} bitwise arithmetic operations", sample.bitops);
            println!("Detected {} cryptographic constants", sample.constants.len());
            println!("Detected {} strings that are commonly seen in ransom notes",
                     sample.strings.len());
            println!("Processed {} in {}.{} seconds",
                     options.fname,
                     time.as_secs(),
                     time.subsec_nanos());
        }

        // Add data to the database.
    }

    Ok(())
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Error::BinaryError => "Error opening binary",
            Error::DisassemblyError => "Error disassembling binary",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Platform::Unix => "unix",
            Platform::Linux => "linux",
            Platform::Windows => "windows",
            Platform::Unknown => "unknown"
        };
        write!(f, "{}", s)
    }
}

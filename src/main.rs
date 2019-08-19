extern crate argparse;
extern crate regex;
extern crate chrono;

#[macro_use]
extern crate lazy_static;

#[macro_use(bson, doc)]
extern crate mongodb;

pub mod binary;
pub mod conversions;
pub mod bfd;
pub mod capstone;
pub mod util;
pub mod statistics;
pub mod graphs;
pub mod sample;

use argparse::{ArgumentParser, StoreTrue, Store};
use binary::binary::Binary;
use chrono::Local;
use mongodb::{Client, Document, ThreadedClient};
use mongodb::db::ThreadedDatabase;
use mongodb::coll::Collection;
use sample::{Sample, SampleType, KEYWORDS};
use statistics::{count_instructions, print_statistics, CSVFile, CSVType};
use std::{fmt, fs, io, process};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

enum Error {
    BinaryError(String),
    DisassemblyError(String),
    VertexSizeError
}

enum DBResult {
    InsertResult(mongodb::coll::results::InsertOneResult),
    UpdateResult(mongodb::coll::results::UpdateResult),
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
    one_sec: String,
    dump_sec: bool,
    symbols: bool,
    disam: bool,
    stats: bool,
    loops: bool,
    analysis: bool,
    server: String,
    port: u16,
    dbname: String,
    collection: String,
    limit: usize,
    sample_type: SampleType,
    csv: bool,
    csv_filename: String,
    verbose: bool,
    all: bool,
}

fn main() -> Result<(), io::Error> {
    // Set default options.
    let mut options: Options = Options {
        fname: String::new(),
        sections: false,
        one_sec: String::new(),
        dump_sec: false,
        symbols: false,
        disam: false,
        stats: false,
        loops: false,
        analysis: false,
        server: "localhost".to_string(),
        port: 27017,
        dbname: "statistics".to_string(),
        collection: String::new(),
        limit: 15000,
        sample_type: SampleType::Unknown,
        csv: false,
        csv_filename: String::new(),
        verbose: false,
        all: false,
    };

    // Set argparse options.
    {
        let mut ap = ArgumentParser::new();

        ap.set_description("Binary analysis tool");
        ap.refer(&mut options.fname)
          .add_argument("file name", Store, "File to analyze.\
                         If a directory is specified, all regular files inside it will\
                         be processed.");
        ap.refer(&mut options.sections)
          .add_option(&["-S", "--sections"],
                      StoreTrue,
                      "Display information in the file's section headers.");
        ap.refer(&mut options.symbols)
          .add_option(&["-s", "--symbols"],
                      StoreTrue,
                      "Display entries in the symbols table.");
        ap.refer(&mut options.one_sec)
          .add_option(&["-c", "--section"],
                      Store,
                      "Show contents of the specified section.");
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
        ap.refer(&mut options.collection)
          .add_option(&["--collection"],
                      Store,
                      "The name of the MongoDB collection to use.");
        ap.refer(&mut options.limit)
          .add_option(&["--limit"],
                      Store,
                      "The maximum number of vertices to process. Large vertex sets \
                      will exhaust memory (default: 15000).");
        ap.refer(&mut options.sample_type)
          .add_option(&["--type"],
                      Store,
                      "A tag for the type of sample under analysis. Valid options are \
                      benign, cryptographic, and ransomware.");
        ap.refer(&mut options.csv)
          .add_option(&["--csv"], StoreTrue, "Dump database contents to a CSV file.");
        ap.refer(&mut options.csv_filename)
          .add_option(&["--csv_file"], Store, "The name of the CSV file to write to.");
        ap.refer(&mut options.verbose)
          .add_option(&["-v", "--verbose"],
                      StoreTrue,
                      "Be verbose.");
        ap.refer(&mut options.all).add_option(&["-A", "--all"],
                                              StoreTrue, "Enable all options");
        ap.parse_args_or_exit();

    }

    // Configure database connection.
    let client = match Client::connect(&options.server, options.port) {
        Ok(client) => client,
        Err(e) => panic!("Database connection failed: {}", e)
    };

    if options.csv {
        write_csv(&options, &client);
        process::exit(0);
    }

    if !(options.fname.len() > 0) {
        eprintln!("Usage: ma [OPTIONS] FILE_NAME");
        process::exit(1);
    }


    // Check for valid sample type.
    match options.sample_type {
        SampleType::Unknown => {
            println!("Invalid sample type. Valid types are: benign, cryptographic, \
                     and ransomware.");
            process::exit(1);
        },
        _ => ()
    };

    if options.all {
        options.sections = true;
        options.symbols = true;
        options.dump_sec = true;
        options.disam = true;
    }

    let collection;
    if options.collection.len() > 0 {
        collection = client.db(&options.dbname).collection(&options.collection)
    }
    else {
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
        collection = client.db(&options.dbname).collection(&platform.to_string());
    }

    // Process all files.
    let mut files: Vec<String> = Vec::new();
    let md = fs::metadata(options.fname.clone()).expect("Unable to open file");

    if md.is_dir() {
        if let Ok(entries) = fs::read_dir(options.fname.clone()) {
            for entry in entries {
                let entry = entry?;
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        if let Some(s) = entry.path().to_str() {
                            files.push(s.to_string());
                        }
                    }
                }
            }
        }
    }
    else {
        files.push(options.fname.clone());
    }

    for file in files {
        match analyze_binary(&file.clone(), &options, &collection) {
            Ok(_) => (),
            Err(e) => {
                println!("Failed to analyze '{}': {}", file, e);
                match collection.insert_one(doc! {"_id": file,
                                                  "error": e.to_string()}, None) {
                    Ok(_) => (),
                    Err(e) => println!("insert_one returned error {}", e)
                };
            }
        };
    }
    Ok(())
}

fn analyze_binary(fname: &str, options: &Options, collection: &Collection)
        -> Result<(), Error> {
    let now = Instant::now();
    let mut b: Binary = match Binary::new(fname.to_string(), options.limit) {
        Ok(bin) => bin,
        Err(e) => return Err(Error::BinaryError(e.to_string()))
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
        b.print_symbols();
    }
    if options.one_sec.len() > 0 {
        if let Some(sec) = b.get_section(&options.one_sec) {
            println!("{}\n", sec);
            util::print_bytes(&sec.bytes);
        }
        else {
            println!("Section '{}' not found", options.one_sec);
        }
        println!("");
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
                return Err(Error::DisassemblyError(e.to_string()));
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
        match b.detect_loops() {
            Some(loops) => println!("Detected {} loops", loops.len()),
            None => return Err(Error::VertexSizeError),
        }
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
            println!("Detected {} external functions",
                     sample.binary.external_functions().len());
            println!("Processed {} in {}.{} seconds",
                     fname.clone(),
                     time.as_secs(),
                     time.subsec_nanos());
        }

        // TODO: Get number of vertices and edges without creating CFG twice.
        let cfg = match sample.binary.cfg() {
            Some(cfg) => cfg,
            None => graphs::CFG {start: 0,
                                 end: 0,
                                 edges: HashSet::new(),
                                 vertices: HashMap::new()}
        };
        let counts = match sample.counts_as_bson() {
            Ok(c) => c,
            Err(e) => {
                println!("to_bson error: {}", e);
                bson!({})
            }
        };

        // Add data to the database.
        insert_or_replace(collection,
                          doc! {"_id": fname.clone()},
                          doc! {"_id": fname.clone(),
                                "bin_type": sample.binary.bin_type.to_string(),
                                "arch": sample.binary.arch.to_string(),
                                "bits": sample.binary.bits,
                                "entry": sample.binary.entry,
                                "bytes": sample.binary.bytes.len() as u64,
                                "sample_type": options.sample_type.to_string(),
                                "elapsed_time": {
                                    "sec": time.as_secs(),
                                    "nano": time.subsec_nanos()},
                                "loops": sample.loops,
                                "bitops": sample.bitops,
                                "constants": {
                                    "count": sample.constants.len() as u64,
                                    "indices": sample.constants
                                                     .iter()
                                                     .map(|&i| bson!(i as u64))
                                                     .collect::<Vec<mongodb::Bson>>(),},
                                "strings": {
                                    "count": sample.strings.len() as u64,
                                    "indices": sample.strings
                                                     .iter()
                                                     .map(|&i| bson!(i as u64))
                                                     .collect::<Vec<mongodb::Bson>>(),},
                                "cfg": {
                                    "vertices": cfg.vertices.len() as u64,
                                    "edges": cfg.edges.len() as u64},
                                "counts": counts,
                                "functions": {
                                    "dsym": sample.binary
                                                  .external_functions()
                                                  .iter()
                                                  .map(|s| bson!(s))
                                                  .collect::<Vec<mongodb::Bson>>()},
                                });
    }

    Ok(())
}

fn insert_or_replace(collection: &Collection, search_for: Document,
                     document: Document) -> DBResult {
    if let Ok(Some(d)) = collection.find_one(Some(search_for), None) {
        return DBResult::UpdateResult(collection.replace_one(d, document, None).unwrap());
    }
    else {
        return DBResult::InsertResult(collection.insert_one(document, None).unwrap());
    }
}

fn write_csv(options: &Options, client: &mongodb::Client) {
    // Used the data as part of the filename.
    let db = client.db(&options.dbname);
    let mut collections: Vec<Collection> = Vec::new();

    if options.collection.len() > 0 {
        collections.push(db.collection(&options.collection));
    }
    else {
        match db.collection_names(None) {
            Ok (cols) => for collection in cols {
                collections.push(db.collection(&collection));
            },
            _ => {
                println!("No collections found in {}", options.dbname);
                process::exit(1);
            }
        };
    }

    let general_info: Vec<String> =vec!["type".to_string(), "arch".to_string(),
                                        "bits".to_string(), "bytes".to_string(),
                                        "elapsed_time".to_string(), "loops".to_string(),
                                        "constants".to_string(), "strings".to_string(),
                                        "vertices".to_string(), "edges".to_string(),
                                        "platform".to_string()];


    let date = Local::today().to_string().replace("-", "_").replace(":", "_");
    CSVFile::new("general_info".to_string() + &date + ".csv",
                 general_info,
                 None,
                 None,
                 &db,
                 None).write();
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Error::BinaryError(e) => format!("Error opening binary: {}", e),
            Error::DisassemblyError(e) => format!("Error disassembling binary: {}", e),
            Error::VertexSizeError => format!("Too many vertices")
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

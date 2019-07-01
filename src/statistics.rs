use binary::binary::{Binary, Instruction};
use capstone;
use graphs;
use mongodb::db::ThreadedDatabase;
use sample::{Sample, SampleType};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::fs::File;
use std::time;

pub fn count_instructions(bin: &Binary) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();

    for insn in bin.instructions() {
        let counter = counts.entry(insn.mnemonic).or_insert(0);
        *counter += 1;
    }

    counts
}

pub fn print_statistics(counts: &HashMap<String, u64>) {
    for (mnemonic, count) in counts {
        println!("{}: {}", mnemonic, count);
    }
}

pub fn is_bitop(insn: &Instruction) -> bool {
    if insn.id == capstone::x86_insn_X86_INS_AND ||
       insn.id == capstone::x86_insn_X86_INS_ANDPS ||
       insn.id == capstone::x86_insn_X86_INS_ANDNPS ||
       insn.id == capstone::x86_insn_X86_INS_ANDN ||
       insn.id == capstone::x86_insn_X86_INS_ANDPD ||
       insn.id == capstone::x86_insn_X86_INS_ANDNPD ||
       insn.id == capstone::x86_insn_X86_INS_PAND ||
       insn.id == capstone::x86_insn_X86_INS_PANDN ||
       insn.id == capstone::x86_insn_X86_INS_OR ||
       insn.id == capstone::x86_insn_X86_INS_ORPS ||
       insn.id == capstone::x86_insn_X86_INS_ORPD ||
       insn.id == capstone::x86_insn_X86_INS_POR ||
       insn.id == capstone::x86_insn_X86_INS_XOR ||
       insn.id == capstone::x86_insn_X86_INS_XORPS ||
       insn.id == capstone::x86_insn_X86_INS_XORPD ||
       insn.id == capstone::x86_insn_X86_INS_PXOR 
       /*
       insn.id == x86_insn_X86_INS_ ||
       insn.id == x86_insn_X86_INS_ ||
       insn.id == x86_insn_X86_INS_ ||
       insn.id == x86_insn_X86_INS_ ||
       insn.id == x86_insn_X86_INS_ ||
       insn.id == x86_insn_X86_INS_ ||
       */
    {
        return true
    }

    false
}

#[derive(Clone)]
pub struct Statistic<'a> {
    pub binary: &'a Binary,
    pub sample: &'a Sample,
    pub sample_type: SampleType,
    pub processing_time: time::Duration
}

impl<'a> Statistic<'_> {
    pub fn most_common_insns(&self, count: usize) -> Vec<(String, u64)> {
        let mut sorted: Vec<(String, u64)> = self.sample
                                                 .counts
                                                 .iter()
                                                 .map(|(k, &v)| (k.clone(), v))
                                                 .collect();
        sorted.sort_by(|x, y| y.1.cmp(&x.1));
        sorted[0..count].to_vec()
    }

    pub fn to_doc(&self) -> mongodb::Document {
        let cfg = match self.binary.cfg() {
            Some(cfg) => cfg,
            None => graphs::CFG {start: 0,
                                 end: 0,
                                 edges: HashSet::new(),
                                 vertices: HashMap::new()}
        };
        let counts = match self.sample.counts_as_bson() {
            Ok(c) => c,
            Err(e) => {
                println!("to_bson error: {}", e);
                bson!({})
            }
        };

        doc! {"_id": self.binary.filename.clone(),
              "bin_type": self.binary.bin_type.to_string(),
              "arch": self.binary.arch.to_string(),
              "bits": self.binary.bits,
              "entry": self.binary.entry,
              "bytes": self.binary.bytes.len() as u64,
              "sample_type": self.sample_type.to_string(),
              "elapsed_time": {
                  "sec": self.processing_time.as_secs(),
                  "nano": self.processing_time.subsec_nanos()},
              "loops": self.sample.loops,
              "bitops": self.sample.bitops,
              "constants": {
                  "count": self.sample.constants.len() as u64,
                  "indices": self.sample.constants
                                        .iter()
                                        .map(|&i| bson!(i as u64))
                                        .collect::<Vec<mongodb::Bson>>(),},
              "strings": {
                  "count": self.sample.strings.len() as u64,
                  "indices": self.sample.strings
                                        .iter()
                                        .map(|&i| bson!(i as u64))
                                        .collect::<Vec<mongodb::Bson>>(),},
              "cfg": {
                  "vertices": cfg.vertices.len() as u64,
                  "edges": cfg.edges.len() as u64},
              "counts": counts,
              "functions": {
                  "dsym": self.binary.external_functions()
                                     .iter()
                                     .map(|s| bson!(s))
                                     .collect::<Vec<mongodb::Bson>>()},
              }
    }
}

pub enum CSVType {
    General,
    Counts,
    Strings,
    Constants
}

pub struct CSVFile<'a> {
    pub filename: String,
    pub header: Vec<String>,
    pub csv_type: CSVType,
    pub db: &'a mongodb::db::Database,
    pub collections: Vec<String>
}

impl<'a> CSVFile<'_> {
    pub fn new(filename: String,
               header: Vec<String>,
               csv_type: CSVType,
               db: &'a mongodb::db::Database,
               collections: Option<&'a [String]>) -> CSVFile<'a> {

        // Only include collections that already exist. Only useful for writing.
        let collection_names = match db.collection_names(None) {
            Ok(names) => names,
            _ => Vec::new()
        };
        let collections = match collections {
            Some(cols) => {
                let mut v: Vec<String> = Vec::new();
                for c in cols {
                    if collection_names.contains(&c) {
                        v.push(c.to_string());
                    }
                }
                v
            },
            None => collection_names
        };

        CSVFile {filename: filename,
                 header: header,
                 csv_type: csv_type,
                 db: db,
                 collections: collections}
    }

    pub fn write(&self) {
        // Open file.
        let mut file = match File::create(&self.filename) {
            Ok(file) => file,
            _ => return
        };

        // Write header to file.
        let header = format!("{},", "name") + &self.header.join(",") + "\n"; 
        file.write(header.as_bytes()).unwrap();

        // Write each line.
        for collection in &self.collections {
            let coll_name = collection.clone();
            let collection = self.db.collection(&collection);

            match collection.find(Some(doc!{"error": {"$exists": false}}), None) {
                Ok(cursor) => {
                    for document in cursor {
                        let document = match document {
                            Ok(doc) => doc,
                            _ => continue
                        };

                        let mut line = String::new();
                        if let Some(value) = document.get(&"_id") {
                            // Capture just the file name and not the full path.
                            match value {
                                mongodb::Bson::String(s) => {
                                    let path: Vec<&str> = s.split("/").collect();
                                    line += &format!("{},", path[path.len() - 1]);
                                },
                                _ => ()
                            };
                        }

                        match self.csv_type {
                            CSVType::General =>
                                line += &self.general_info(document, coll_name.clone()),
                            CSVType::Counts => line += &self.counts(document),
                            CSVType::Strings => line += &self.strings(document),
                            CSVType::Constants => line += &self.constants(document)
                        };
                        line.pop(); // Remove trailing ','.
                        line += "\n";
                        file.write(line.as_bytes()).unwrap();
                    }
                },
                _ => continue
            };
        }
    }

    fn general_info(&self, doc: mongodb::Document, coll_name: String) -> String {
        let mut line = String::new();

        for field in &self.header {
            if field == "elapsed_time" {
                match doc.get(&field) {
                    Some(value) => match value {
                        mongodb::Bson::Document(edoc) => {
                            if let Some(sec) = edoc.get(&"sec") {
                                match sec {
                                    mongodb::Bson::I64(n) => line += &n.to_string(),
                                    mongodb::Bson::I32(n) => line += &n.to_string(),
                                    _ => eprintln!("'seconds' not an integer")
                                };
                            }
                            if let Some(nano) =  edoc.get(&"nano") {
                                match nano {
                                    mongodb::Bson::I64(n) => line += &format!(".{}", n),
                                    mongodb::Bson::I32(n) => line += &format!(".{}", n),
                                    _ => eprintln!("'seconds' not an integer")
                                };
                            }
                        },
                        _ => eprintln!("'elapsed_time' is not a document")
                    },
                    _ => eprintln!("'elapsed_time' doesn't exist in this document")
                };
            }
            else if field == "constants" ||
                    field == "strings" ||
                    field == "constants" {
                match doc.get(&field) {
                    Some(value) => match value {
                        mongodb::Bson::Document(cdoc) => {
                            if let Some(sec) = cdoc.get(&"count") {
                                match sec {
                                    mongodb::Bson::I64(n) =>
                                        line += &format!("{},", n),
                                    mongodb::Bson::I32(n) =>
                                        line += &format!("{},", n),
                                    _ => eprintln!("'count' not an integer")
                                };
                            }
                        },
                        _ => println!("'{}' is not a document", field)
                    },
                    _ => println!("'{}' doesn't exist in this document", field)
                }
            }
            else if field == "vertices" || field == "edges" {
                match doc.get(&"cfg") {
                    Some(value) => match value {
                        mongodb::Bson::Document(cdoc) => {
                            if let Some(count) = cdoc.get(&field) {
                                match count {
                                    mongodb::Bson::I64(n) =>
                                        line += &format!("{},", n),
                                    mongodb::Bson::I32(n) =>
                                        line += &format!("{},", n),
                                    _ => eprintln!("'{}' not an integer", field)
                                };
                            }
                        },
                        _ => println!("'cfg' is not a document")
                    },
                    _ => println!("'cfg' doesn't exist in this document")
                }
            }
            else if field == "type" {
                match doc.get(&"type") {
                    Some(value) => match value {
                        mongodb::Bson::String(s) => {
                            if s == "ELF" || s == "PE" {
                                line += "benign,";
                            }
                            else {
                                line += &s.to_string();
                            }
                        },
                        _ => println!("'type' is not a string")
                    },
                    _ => println!("'type' not in document")
                };
            }
            else if field == "platform" {
                line += &format!("{},", coll_name);
            }
            else {
                match doc.get(&field) {
                    Some(value) => line += &format!("{},", value.to_string()),
                    None => line += ","
                };
            }
        }

        line
    }

    fn counts(&self, doc: mongodb::Document) -> String {
        let mut line = String::new();
        let mut counts: HashMap<String, u64> = HashMap::new();

        match doc.get(&"counts") {
            Some(value) => match value {
                mongodb::Bson::Document(cdoc) => {
                    for (k, v) in cdoc.iter() {
                        match v {
                            mongodb::Bson::I32(n) => counts.insert(k.to_string(),
                                                                   *n as u64),
                            mongodb::Bson::I64(n) => counts.insert(k.to_string(),
                                                                   *n as u64),
                            _ => {
                                eprintln!("instruction count is not an integer");
                                None
                            }
                        };
                    }
                },
                _ => println!("'counts' not a document")
            },
            _ => println!("'counts' doesn't exist in this document")
        };

        for field in &self.header[1..] {
            match counts.get(&field.clone()) {
                Some(count) => line += &format!("{},", count),
                None => line += "0,"
            };
        }
        line
    }

    fn strings(&self, doc: mongodb::Document) -> String {
        let mut line = String::new();
        let flags = self.get_array("strings".to_string(), &doc);

        for num in flags {
            line += &format!("{},", num);
        }

        line
    }

    fn constants(&self, doc: mongodb::Document) -> String {
        let mut line = String::new();
        let flags = self.get_array("constants".to_string(), &doc);

        for num in flags {
            line += &format!("{},", num);
        }

        line
    }

    fn get_array(&self, name: String, doc: &mongodb::Document) -> Vec<u8> {
        let mut flags = vec![0; self.header.len()];

        match doc.get(&name) {
            Some(value) => match value {
                mongodb::Bson::Document(sdoc) => {
                    if let Some(indices) = sdoc.get(&"indices") {
                        match indices {
                            mongodb::Bson::Array(arr) => for i in arr {
                                match i {
                                    mongodb::Bson::I32(i) => flags[*i as usize] = 1,
                                    mongodb::Bson::I64(i) => flags[*i as usize] = 1,
                                    _ => println!("Array elements not integers")
                                };
                            },
                            _ => println!("'indices' not an array")
                        }
                    }
                    else {
                        println!("'indices' not in strings");
                    }
                },
                _ => println!("'{}' not a document", name)
            },
            _ => println!("'{}' not found in document", name)
        };

        flags
    }
}

pub fn most_unique_insns(samples: Vec<Sample>) {
}

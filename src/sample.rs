use binary::binary::Binary;
use regex::bytes::RegexSet;
use statistics;
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;

pub struct Sample{
    pub binary: Binary,
    pub counts: HashMap<String, u64>,
    pub bitops: u64,
    pub loops: u64,
    pub strings: Vec<usize>,
    pub constants: Vec<usize>
}

impl Sample {
    /** Creates a instance of a Sample without any analysis preformed. Disassembles the
     * binary if it has not already been disassembled.
     */
    pub fn new(mut bin: Binary) -> Sample {
        if bin.blocks.len() == 0 {
            match bin.disassemble() {
                Ok(_) => (),
                Err(e) => panic!("Disassembly failed! {}", e)
            };
        }

        Sample {binary: bin,
                counts: HashMap::new(),
                bitops: 0,
                loops: 0,
                strings: Vec::new(),
                constants: Vec::new()}
    }

    pub fn analysis(&mut self) {
        let (loop_tx, loop_rx) = mpsc::channel();
        let mut bin = self.binary.clone();
        thread::spawn(move || {
            loop_tx.send(bin.detect_loops().len() as u64).unwrap();
        });

        let (count_tx, count_rx) = mpsc::channel();
        bin = self.binary.clone();
        thread::spawn(move || {
            count_tx.send(statistics::count_instructions(&bin)).unwrap();
        });

        let (bitop_tx, bitop_rx) = mpsc::channel();
        bin = self.binary.clone();
        thread::spawn(move || {
            bitop_tx.send(bin.instructions()
                             .iter()
                             .filter(|i| statistics::is_bitop(i))
                             .collect::<Vec<_>>()
                             .len() as u64).unwrap();
        });

        let (strings_tx, strings_rx) = mpsc::channel();
        bin = self.binary.clone();
        thread::spawn(move || {
            strings_tx.send(Sample::strings(&bin)).unwrap();
        });

        let (constants_tx, constants_rx) = mpsc::channel();
        bin = self.binary.clone();
        thread::spawn(move || {
            constants_tx.send(Sample::constants(&bin)).unwrap();
        });

        self.counts = match count_rx.recv() {
            Ok(counts) => counts,
            Err(e) => panic!("Receiving counts failed! {}", e)
        };

        self.bitops = match bitop_rx.recv() {
            Ok(bitops) => bitops,
            Err(e) => panic!("Receiving bitops failed! {}", e)
        };

        self.strings = match strings_rx.recv() {
            Ok(strings) => strings,
            Err(e) => panic!("Receiving strings failed! {}", e)
        };

        self.constants = match constants_rx.recv() {
            Ok(constants) => constants,
            Err(e) => panic!("Receiving constants failed! {}", e)
        };

        self.loops = match loop_rx.recv() {
            Ok(loops) => loops,
            Err(e) => panic!("Receiving loops failed! {}", e)
        };

    }

    pub fn strings(bin: &Binary) -> Vec<usize> {
        lazy_static! {
            static ref KW_SET: RegexSet = match RegexSet::new(&KEYWORDS) {
                Ok(set) => set,
                Err(e) => panic!("Error creating keyword regex set: {}", e)
            };
        }
        KW_SET.matches(bin.bytes.as_slice()).into_iter().collect()
    }

    pub fn constants(bin: &Binary) -> Vec<usize> {
        lazy_static! {
            static ref CONST_SET: RegexSet = match RegexSet::new(&CONSTANTS) {
                Ok(set) => set,
                Err(e) => panic!("Error creating keyword regex set: {}", e)
            };
        }
        CONST_SET.matches(bin.bytes.as_slice()).into_iter().collect()
    }
}

#[derive(Clone)]
pub enum Constants {
}

static KEYWORDS: [&'static str;   9] = [r"aes",
                                        "rsa",
                                        "des",
                                        "chacha",
                                        "ransom",
                                        "encrypt",
                                        "AES",
                                        "RSA",
                                        "DES"];
static CONSTANTS: [&'static str; 0] = [];

use binary::binary::{Binary, Instruction};
use capstone;
use graphs;
use sample::{Sample, SampleType};
use std::collections::{HashMap, HashSet};
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
              "type": self.binary.bin_type.to_string(),
              "arch": self.binary.arch.to_string(),
              "bits": self.binary.bits,
              "entry": self.binary.entry,
              "bytes": self.binary.bytes.len() as u64,
              "type": self.sample_type.to_string(),
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

pub fn most_unique_insns(samples: Vec<Sample>) {
}

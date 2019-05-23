use std::collections::{HashMap};
use std::ffi::{CStr};
use binary::binary::Binary;

include!(concat!(env!("OUT_DIR"), "/bgen_capstone.rs"));

pub fn count_instructions(bin: &Binary) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();

    for block in &bin.instructions {
        for insn in block {
            unsafe {
                let mnemonic = CStr::from_ptr((*insn).mnemonic.as_ptr()).to_string_lossy();
                let counter = counts.entry(mnemonic.to_string()).or_insert(0);
                *counter += 1;
            }
        }
    }

    counts
}

pub fn print_statistics(counts: &HashMap<String, u64>) {
    for (mnemonic, count) in counts {
        println!("{}: {}", mnemonic, count);
    }
}

fn is_bitop(insn: cs_insn) -> bool {
    unsafe {
        if insn.id == x86_insn_X86_INS_AND ||
           insn.id == x86_insn_X86_INS_ANDPS ||
           insn.id == x86_insn_X86_INS_ANDNPS ||
           insn.id == x86_insn_X86_INS_ANDN ||
           insn.id == x86_insn_X86_INS_ANDPD ||
           insn.id == x86_insn_X86_INS_ANDNPD ||
           insn.id == x86_insn_X86_INS_PAND ||
           insn.id == x86_insn_X86_INS_PANDN ||
           insn.id == x86_insn_X86_INS_OR ||
           insn.id == x86_insn_X86_INS_ORPS ||
           insn.id == x86_insn_X86_INS_ORPD ||
           insn.id == x86_insn_X86_INS_POR ||
           insn.id == x86_insn_X86_INS_XOR ||
           insn.id == x86_insn_X86_INS_XORPS ||
           insn.id == x86_insn_X86_INS_XORPD ||
           insn.id == x86_insn_X86_INS_PXOR 
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
    }

    false
}

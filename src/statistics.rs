use std::collections::HashMap;
use binary::binary::{Binary, Instruction};
use capstone;

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

use std::fmt;
use bfd::load_binary;
use std::ffi::CStr;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use super::section::*;
use super::symbol::*;
use super::super::util::print_bytes;
use super::super::capstone;
use super::super::graphs;

pub enum LoadError {
    SectionNotFound,
    FileNotFound,
    OpenFileError,
    InvalidFormat,
    UnrecognizedFormat,
    UnsupportedType,
    UnsupportedArch,
    NoSymbols,
    SecReadErr,
}

#[derive(Clone)]
pub enum BinaryType {
    BinTypeAuto,
    BinTypeELF,
    BinTypePE,
}

#[derive(Clone)]
pub enum BinaryArch {
    ArchNone,
    ArchX86,
    ArchArm,
    ArchX86_64,
    ArchArm64,
    ArchRISCV,
}

#[derive(Clone)]
pub struct Binary {
    pub filename: String,
    pub bin_type: BinaryType,
    pub type_str: String,
    pub arch: BinaryArch,
    pub arch_str: String,
    pub bits: u32,
    pub entry: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub functions: Vec<Function>,
    pub blocks: Vec<BasicBlock>,
    pub bytes: Vec<u8>,
    pub max_vertices: usize
}

impl Binary {
    pub fn new<'b>(fname: String, max_vertices: usize) -> Result<Binary, LoadError> {
        let mut bin = match load_binary(fname.clone()) {
            Ok(bin) => bin,
            Err(e) => return Err(e)
        };

        bin.max_vertices = max_vertices;
        Ok(bin)
    }

    pub fn disassemble(&mut self) -> Result<(), capstone::cs_err> {
        self.blocks = match capstone::disassemble(self){
            Ok(blocks) => blocks,
            Err(e) => return Err(e),
        };
        Ok(())
    }

    /** Returns a HashSet of Instruction.
     */
    pub fn instructions(&self) -> HashSet<Instruction> {
        let mut instructions: HashSet<Instruction> = HashSet::new();

        for block in &self.blocks {
            for instruction in &block.instructions {
                instructions.insert(instruction.clone());
            }
        }
        instructions
    }

    pub fn cfg(&self) -> Option<graphs::CFG> {
        graphs::CFG::new(self)
    }

    pub fn detect_loops(&self, ) -> Option<Vec<graphs::Loop>> {
        let mut loops: Vec<graphs::Loop> = Vec::new();

        if let Some(cfg) = graphs::CFG::new(self) {
            if cfg.vertices.len() > self.max_vertices {
                return None;
            }
            let subgraphs = cfg.components();

            for subgraph in &subgraphs {
                let mut dj = graphs::DJGraph::new(&subgraph, subgraph.start);
                let mut l = dj.detect_loops();
                loops.append(&mut l);
            }
        }

        Some(loops)
    }

    pub fn get_text_section<'c>(self) -> Result<Section, LoadError> {
        for section in self.sections.iter() {
            if section.name == ".text" {
                return Ok(section.clone())
            }
        }
        Err(LoadError::SectionNotFound)
    }

    pub fn is_addr_section(&self, addr: u64) -> Option<String> {
        for section in self.sections.iter() {
            if section.vma == addr {
                return Some(section.name.clone());
            }
        }
        None
    }

    pub fn is_addr_symbol(&self, addr: u64) -> Option<String> {
        for symbol in self.symbols.iter() {
            if symbol.addr == addr {
                return Some(symbol.name.clone());
            }
        }
        None
    }

    pub fn print_symbols(&self) {
        fn print_syms(symbols: &Vec<Symbol>) {
            println!("{:<6} {:<18} {:<4} {:<6} {:<}", "Num", "Value", "Type",
                     "Bind", "Name");
            let mut i = 0;
            for symbol in symbols {

                println!("{:5}: {}", i, symbol);
                i += 1;
            }
        }

        // Sort static and dynamic symbols into their own vectors. Note that there
        // were issues encountered using collec() and so this work around was used.
        let mut dsymtab: Vec<Symbol> = Vec::new();
        let mut ssymtab: Vec<Symbol> = Vec::new();
        for sym in self.symbols.iter() {
            match sym.table {
                SymbolTable::SymTabStatic => ssymtab.push((*sym).clone()),
                SymbolTable::SymTabDynamic => dsymtab.push(sym.clone()),
            };
        }

        println!("Dynamic symbol table:");
        print_syms(&dsymtab);
        println!("\nStatic symbol table:");
        print_syms(&ssymtab);
        print!("\n");
    }

    pub fn print_sections(&self) {
        println!("\nSections:");
        println!("{:24} {:4} {:18} {}", "Name", "Type", "Address", "Size");
        for sec in self.sections.iter() {
            println!("{}", sec);
        }
        print!("\n");
    }

    pub fn print_section_contents(&self) {
        for section in self.sections.iter() {
            println!("{}", section.name);
            print_bytes(&section.bytes);
        }
    }

    pub fn external_functions(&self) -> Vec<String> {
        self.symbols.iter()
                    .filter(|s| s.sym_type == SymbolType::SymTypeFunc &&
                                s.table == SymbolTable::SymTabDynamic)
                    .map(|s| s.name.clone())
                    .collect()
    }

    pub fn get_section(&self, name: &str) -> Option<Section> {
        for section in &self.sections {
            if section.name == name {
                return Some(section.clone());
            }
        }
        None
    }
}

impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut b_str = String::new();
        for function in self.functions.iter() {
            b_str.push_str(&format!("{}\n", function));
        }
        write!(f, "{}", b_str)
    }
}

#[derive(Clone)]
pub struct Function {
    pub name: String,
    pub addr: u64,
    pub comment: String,
    pub basic_blocks: Vec<BasicBlock>,
}

impl Function {
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bb_str = self.basic_blocks.iter()
                                      .map(|ref ins| format!("{}", ins))
                                      .collect::<Vec<String>>()
                                      .join("\n\t|\n\tv\n");
        write!(f, "{}\n{}\n", self.comment, bb_str)
    }
}

#[derive(Clone, Eq, Debug)]
pub struct BasicBlock {
    pub entry: u64,
    pub size: u64,
    pub references: HashSet<u64>,
    pub instructions: Vec<Instruction>,
}

impl BasicBlock {
    pub fn new(instructions: Vec<Instruction>) -> BasicBlock {
        BasicBlock {
            entry: instructions[0].address,
            size: instructions.iter().fold(0, |acc, ins| acc + ins.size) as u64,
            references: HashSet::new(),
            instructions: instructions,
        }
    }

    pub fn split(&self, addr: u64, xref: Option<HashSet<u64>>) ->
      Option<(BasicBlock, BasicBlock)> {
        if addr == self.entry {
            return None;
        }

        let mut offset: usize = 0;
        let mut found_offset: bool = false;
        for i in 0..self.instructions.len() - 1 {
            if self.instructions[i].address == addr {
                offset = i;
                found_offset = true;
                break;
            }
        }
        if !found_offset {
            return None;
        }

        let low_block = BasicBlock {
                            entry: self.entry,
                            size: addr - self.entry,
                            references: self.references.clone(),
                            instructions: self.instructions[..offset].to_vec(),
                        };
        let high_size = self.size - low_block.size;
        Some((low_block,
              BasicBlock {
                  entry: addr,
                  size: high_size,
                  references: match xref {
                      Some(xref) => xref,
                      None => HashSet::new(),
                  },
                  instructions: self.instructions[offset..].to_vec(),
              }))
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.entry <= addr && addr < self.entry + self.size
    }

    pub fn returns(&self) -> bool {
        let insn = &self.instructions[self.instructions.len() - 1];

        insn.has_group(capstone::x86_insn_group_X86_GRP_RET) ||
        insn.has_group(capstone::x86_insn_group_X86_GRP_IRET)
    }

    pub fn has_call(&self) -> bool {
        self.instructions[self.instructions.len() - 1].id ==
            capstone::x86_insn_X86_INS_CALL
    }
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ref_str = self.references.iter()
                                     .map(|x| format!("0x{:X}", x).to_string())
                                     .collect::<Vec<String>>()
                                     .join(", ");
        let bb_str = self.instructions.iter()
                                      .map(Instruction::to_string)
                                      .collect::<Vec<String>>()
                                      .join("\n");
        if ref_str.len() > 0 {
            write!(f, "; XREF from {}\n{}", ref_str, bb_str)
        }
        else {
            write!(f, "{}", bb_str)
        }
    }
}

impl Ord for BasicBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        self.entry.cmp(&other.entry)
    }
}

impl PartialOrd for BasicBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for BasicBlock {
    fn eq(&self, other: &Self) -> bool {
        self.entry == other.entry
    }
}

impl Hash for BasicBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.entry.hash(state);
    }
}

impl graphs::Vertex for BasicBlock {
    fn get_id(&self) -> u32 {
        self.entry as u32
    }
}

#[derive(Clone, Eq, Debug)]
pub struct Instruction {
    pub id: u32,
    pub address: u64,
    pub size: u16,
    pub bytes: [u8; 16usize],
    pub mnemonic: String,
    pub op_str: String,
    pub detail: capstone::cs_detail,
}

impl Instruction {
    pub fn new(insn: capstone::cs_insn) -> Instruction {
        unsafe {
            Instruction{
                id: insn.id,
                address: insn.address,
                size: insn.size,
                bytes: insn.bytes,
                mnemonic: CStr::from_ptr(insn.mnemonic.as_ptr()).to_string_lossy()
                                                         .to_string(),
                op_str: CStr::from_ptr(insn.op_str.as_ptr()).to_string_lossy()
                                                               .to_string(),
                detail: (*insn.detail).clone()
            }
        }
    }

    pub fn is_unconditional_cflow_ins(&self) -> bool {
        self.id == capstone::x86_insn_X86_INS_JMP ||
        self.id == capstone::x86_insn_X86_INS_LJMP ||
        self.id == capstone::x86_insn_X86_INS_RET ||
        self.id == capstone::x86_insn_X86_INS_RETF ||
        self.id == capstone::x86_insn_X86_INS_RETFQ
    }

    /* Determines whether or not an instruction changes control flow of the program.
     *
     * Input: A constant pointer to a cs_insn.
     * Output: A boolean value.
     */
    pub fn is_cflow_ins(&self) -> bool {
        for group in &self.detail.groups {
            if self.is_cflow_group(*group as u32) {
                return true;
            }
        }
        false
    }

    fn is_cflow_group(&self, group: u32) -> bool {
        group == capstone::cs_group_type_CS_GRP_JUMP ||
        group == capstone::cs_group_type_CS_GRP_CALL ||
        group == capstone::cs_group_type_CS_GRP_RET ||
        group == capstone::cs_group_type_CS_GRP_IRET
    }

    pub fn get_immediate_target(&self) -> Option<u64> {
        unsafe {
            let mut op: &capstone::cs_x86_op;

            for i in 0..self.detail.groups_count as usize {
                if self.is_cflow_group(self.detail.groups[i].into()) {
                    for j in 0..self.detail.__bindgen_anon_1.x86.op_count {
                        op = &self.detail.__bindgen_anon_1.x86.operands[j as usize];
                        if (*op).type_ == capstone::x86_op_type_X86_OP_IMM {
                            return Some((*op).__bindgen_anon_1.imm as u64);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn has_group(&self, group: u32) -> bool {
        for grp in &self.detail.groups {
            if *grp as u32 == group {
                return true;
            }
        }
        false
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut ins_str = String::new();

        ins_str.push_str(&format!("0x{:013x} ", self.address));
        for i in 0..16 {
            if i < self.size as usize {
                ins_str.push_str(&format!("{:02x}", self.bytes[i]));
            }
            else {
                ins_str.push_str(&format!("  "));
            }
        }
        ins_str.push_str(&format!(" {} {}", self.mnemonic, self.op_str));

        write!(f, "{}", ins_str)
    }
}

impl PartialEq for Instruction {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.address == other.address &&
        self.size == other.size && self.bytes == other.bytes &&
        self.mnemonic == other.mnemonic && self.op_str == other.op_str &&
        self.detail == other.detail
    }
}

impl Hash for Instruction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.address.hash(state);
        self.size.hash(state);
        self.bytes.hash(state);
        self.mnemonic.hash(state);
        self.op_str.hash(state);
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            LoadError::SectionNotFound => "Section not found",
            LoadError::FileNotFound => "File not found",
            LoadError::OpenFileError => "Error opening file",
            LoadError::InvalidFormat => "Invalid format",
            LoadError::UnrecognizedFormat => "Unrecognized format",
            LoadError::UnsupportedType => "Unsupported type",
            LoadError::UnsupportedArch => "Unsupported architecture",
            LoadError::NoSymbols => "No symbols found",
            LoadError::SecReadErr => "Error reading sections",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for BinaryType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            BinaryType::BinTypeAuto => "Auto",
            BinaryType::BinTypeELF => "ELF",
            BinaryType::BinTypePE => "PE",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for BinaryArch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            BinaryArch::ArchNone => "None",
            BinaryArch::ArchX86 => "x86",
            BinaryArch::ArchArm => "arm",
            BinaryArch::ArchX86_64 => "x86_64",
            BinaryArch::ArchArm64 => "arm64",
            BinaryArch::ArchRISCV => "RISC V",
        };
        write!(f, "{}", s)
    }
}

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Include FFI function generated by bindgen.
include!(concat!(env!("OUT_DIR"), "/bgen_capstone.rs"));

use std::fmt;
use bfd::load_binary;
use std::ffi::CStr;
use std::collections::HashSet;
use super::section::*;
use super::symbol::*;
use super::super::util::print_bytes;
use super::super::capstone;

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
    pub instructions: Vec<Vec<capstone::cs_insn>>,
}

impl Binary {
    pub fn new<'b>(fname: String) -> Result<Binary, LoadError> {
        load_binary(fname.clone())
    }

    pub fn disassemble(&mut self) -> Result<(), cs_err> {
        self.instructions = match capstone::disassemble(self){
            Ok(instructions) => instructions,
            Err(e) => return Err(e),
        };
        Ok(())
    }

    pub fn analyze(&self) {
        let instruction_blocks = capstone::disassemble(self);
        let mut functions: Vec<Function> = Vec::new();


        for block in instruction_blocks {
            let mut basic_blocks: Vec<BasicBlock> = Vec::new();
            let mut instructions: Vec<Instruction> = Vec::new();

            for ins in block {
            }
        }
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

#[derive(Clone)]
pub struct BasicBlock {
    pub entry: u64,
    pub size: u64,
    pub references: HashSet<u64>,
    pub instructions: Vec<capstone::cs_insn>,
}

impl BasicBlock {
    pub fn new(instructions: Vec<capstone::cs_insn>) -> BasicBlock {
        BasicBlock {
            entry: instructions[0].address,
            size: instructions.len() as u64,
            references: HashSet::new(),
            instructions: instructions
        }
    }

    pub fn split(self, addr: u64, xref: Option<u64>) -> Option<(BasicBlock, BasicBlock)> {
        if addr == self.entry {
            return None;
        }

        let offset: usize = (addr - self.entry) as usize;
        let low_block = BasicBlock {
                            entry: self.entry,
                            size: addr - self.entry,
                            references: self.references,
                            instructions: self.instructions[..offset - 1].to_vec()
                        };
        let high_size = self.size - low_block.size;
        Some((low_block,
              BasicBlock {
                  entry: addr,
                  size: high_size,
                  references: match xref {
                      Some(xref) => {
                          let mut set: HashSet<u64> = HashSet::new();
                          set.insert(xref);
                          set
                      },
                      None => HashSet::new(),
                  },
                  instructions: self.instructions[offset..].to_vec(),
              }))
    }

    pub fn contains(self, addr: u64) -> bool {
        self.entry <= addr && addr <= self.entry + self.size
    }
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bb_str = self.instructions.iter()
                                      .map(capstone::cs_insn::to_string)
                                      .collect::<Vec<String>>()
                                      .join("\n");
        write!(f, "{}", bb_str)
    }
}

pub struct Instruction {
    pub instruction: capstone::cs_insn,
}

impl Instruction {
    pub fn new(ins: capstone::cs_insn) -> Instruction {
        Instruction{instruction: ins}
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut ins_str = String::new();

        unsafe {
            ins_str.push_str(&format!("0x{:013x} ", self.instruction.address));
            for i in 0..16 {
                if i < self.instruction.size as usize {
                    ins_str.push_str(&format!("{:02x}", self.instruction.bytes[i]));
                }
                else {
                    ins_str.push_str(&format!("  "));
                }
            }
            let mnemonic = CStr::from_ptr(self.instruction.mnemonic.as_ptr())
                                 .to_string_lossy();
            let op_str = CStr::from_ptr(self.instruction.op_str.as_ptr())
                               .to_string_lossy();
            ins_str.push_str(&format!(" {} {}", mnemonic, op_str));
        }

        write!(f, "{}", ins_str)
    }
}

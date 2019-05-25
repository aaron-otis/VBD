#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Include FFI function generated by bindgen.
include!(concat!(env!("OUT_DIR"), "/bgen_capstone.rs"));

extern crate libc;

use std::fmt;
use std::ffi::CStr;
use std::collections::{HashSet, VecDeque};
use binary::binary::{Binary, BinaryArch, Function, Instruction, BasicBlock};
use binary::symbol::SymbolType;

/* Disassembles a binary. Currently only supports disassembling the .text section.
 *
 * Input:   A reference to a Binary object, bin.
 * Output:  A vector of vectors of capstone::cs_insn each representing
 *          recursively disassembled instructions upon successful disassembly or
 *          cs_err on error.
 */
pub fn disassemble(bin: &Binary) -> Result<Vec<Vec<cs_insn>>, cs_err> {
    //let mut functions: Vec<Function> = Vec::new();
    let mut instruction_blocks: Vec<Vec<cs_insn>> = Vec::new();

    // Get .text section of the binary.
    let text = match bin.clone().get_text_section() {
        Ok(sec) => sec,
        _ => return Ok(Vec::new()),
    };

    // Initialize capstone and get the handle for this binary.
    let mut handle = match cap_open(bin) {
        Ok(d) => d,
        Err(_) => return Err(cs_err_CS_ERR_HANDLE),
    };

    unsafe {
        /* Set option to enable detailed disassembly.
         * Note: If using cs_disasm_iter, this option must be set before
         *       calling cs_malloc, otherwise a segfault will occur!
         */
        match cs_option(handle, cs_opt_type_CS_OPT_DETAIL,
                        cs_opt_value_CS_OPT_ON as usize)  {
            cs_err_CS_ERR_OK => (),
            _ => return Err(cs_err_CS_ERR_OPTION),
        }

        let cs_ins: *mut cs_insn = cs_malloc(handle);
        if cs_ins.is_null() {
            return Err(cs_err_CS_ERR_MEM);
        }

        // @FunType used to differentiate sections from symbols for printing.
        enum FunType {Symbol, Section, Unknown}

        // Create a queue for entry points and add addresses to the queue.
        let mut addr_queue: VecDeque<(String, u64, FunType)> = VecDeque::new();

        // Create a hash set to track which addresses have been processed.
        let mut seen: HashSet<u64> = HashSet::new();

        // Add known functions to the queue.
        if text.contains(bin.entry) {
            addr_queue.push_back((".text".to_string(),
                                  bin.entry,
                                  FunType::Section));
        }
        for symbol in bin.symbols.iter() {
            match symbol.sym_type  {
                SymbolType::SymTypeFunc => {
                    if text.contains(symbol.addr) {
                        addr_queue.push_back((symbol.name.clone(), symbol.addr,
                                         FunType::Symbol));
                    };
                },
                _ => (),
            }
        }

        // Recursive disassembly.
        while !addr_queue.is_empty() {
            let (name, address, ftype) = addr_queue.pop_front()
                                                   .expect("addr_queue");
            let mut addr = address;
            match seen.get(&addr) {
                Some(_) => continue,
                _ =>  (),
            }
            let comment = match ftype {
                FunType::Symbol => format!("{}: ; sym@0x{:013x}", name, addr),
                FunType::Section => format!("{} ; sec@0x{:013x}", name, addr),
                FunType::Unknown => format!("; fun@0x{:013x}", addr),
            };
            let offset = addr - text.vma;
            let pc = &mut text.bytes.as_ptr().offset(offset as isize);
            let mut size = (text.size - offset) as usize;

            //let mut basic_blocks: Vec<BasicBlock> = Vec::new();
            //let mut instructions: Vec<Instruction> = Vec::new();
            let mut instructions: Vec<cs_insn> = Vec::new();

            while cs_disasm_iter(handle, pc, &mut size, &mut addr, cs_ins) {
                if (*cs_ins).id == x86_insn_X86_INS_INVALID || (*cs_ins).size == 0 {
                    break;
                }

                seen.insert((*cs_ins).address);
                instructions.push(*cs_ins);
                //instructions.push(Instruction{instruction: *cs_ins});
                //print_ins(*cs_ins);

                if is_cflow_ins(cs_ins) {
                    // We found the end of a basic block, Add it to the vector.
                    //basic_blocks.push(BasicBlock{instructions: instructions});
                    //instructions = Vec::new();

                    match get_immediate_target(cs_ins) {
                        Some(target_addr) => {
                            match seen.get(&target_addr) {
                                None => {
                                    if text.contains(target_addr) {
                                        addr_queue.push_back(("".to_string(),
                                                              target_addr,
                                                              FunType::Unknown));
                                    }
                                },
                                Some(_) => (),
                            };
                        },
                        None => (),
                    };

                    /* Stop printing once an unconditional control flow
                     * instruction has been encountered.
                     */
                    if is_unconditional_cflow_ins(cs_ins) {
                        // We found the end of a function, add it to the vector.
                        instruction_blocks.push(instructions);
                        /*
                        functions.push(Function{name: name.clone(),
                                                addr: addr,
                                                comment: comment,
                                                basic_blocks: basic_blocks});
                         */
                        break;
                    }
                }
                if (*cs_ins).id == x86_insn_X86_INS_HLT {
                    break;
                }
            }
        }

        // Cleanup.
        cs_free(cs_ins, 1);
        cs_close(&mut handle);
    }

    Ok(instruction_blocks)
}

/* Wrapper to automatically initialize capstone based on binary attributes.
 * Currently only supports x86 and x86_64.
 *
 * Input:   A reference to a Binary object, bin.
 * Output:  A Result of csh on success and cs_err on failure.
 */
fn cap_open(bin: &Binary) -> Result<csh, cs_err> {
    let arch = match bin.arch {
        BinaryArch:: ArchX86 => cs_arch_CS_ARCH_X86,
        BinaryArch::ArchX86_64 => cs_arch_CS_ARCH_X86,
        //BinaryArch::ArchArm => cs_arch_CS_ARCH_ARM,
        //BinaryArch::ArchArm64 => cs_arch_CS_ARCH_ARM64,
        _ => return Err(cs_err_CS_ERR_ARCH),
    };
    let mode = match bin.bits {
        32 => cs_mode_CS_MODE_32,
        64 => cs_mode_CS_MODE_64,
        _ => cs_mode_CS_MODE_LITTLE_ENDIAN, // Default according to capstone.h.
    };

    let mut handle: csh = 0;
    unsafe {
        match cs_open(arch, mode, &mut handle) {
            cs_err_CS_ERR_OK => Ok(handle),
            e => Err(e),
        }
    }
}

/* Print a single instruction.
 *
 * Input:   A single instruction represented as a cs_insn.
 * Output:  None.
 */
pub fn print_ins(ins: cs_insn) {
    unsafe {
        print!("0x{:013x} ", ins.address);
        for i in 0..16 {
            if i < ins.size as usize {
                print!("{:02x}", ins.bytes[i]);
            }
            else {
                print!("  ");
            }
        }
        let mnemonic = CStr::from_ptr(ins.mnemonic.as_ptr()).to_string_lossy();
        let op_str = CStr::from_ptr(ins.op_str.as_ptr()).to_string_lossy();
        println!(" {} {}", mnemonic, op_str);
    }
}

/* Check if an instruction is an unconditional control flow type
 * (i.e a jump).
 */
fn is_unconditional_cflow_ins(ins: *const cs_insn) -> bool {
    let id: u32;

    unsafe {
        id = (*ins).id;
    }

    return id == x86_insn_X86_INS_JMP || id == x86_insn_X86_INS_LJMP ||
           id == x86_insn_X86_INS_RET || id == x86_insn_X86_INS_RETF ||
           id == x86_insn_X86_INS_RETFQ;
}

fn is_cflow_ins(ins: *const cs_insn) -> bool {
    unsafe {
        for i in 0..(*(*ins).detail).groups_count as usize {
            let group = (*(*ins).detail).groups[i];
            if is_cflow_group(group.into()) {
                return true;
            }
        }
    }
    false
}

fn is_cflow_group(group: u32) -> bool {
    return group == cs_group_type_CS_GRP_JUMP ||
           group == cs_group_type_CS_GRP_CALL ||
           group == cs_group_type_CS_GRP_RET ||
           group == cs_group_type_CS_GRP_IRET;
}

fn get_immediate_target(ins: *const cs_insn) -> Option<u64> {
    unsafe {
        let mut op: *mut cs_x86_op;

        for i in 0..(*(*ins).detail).groups_count as usize {
            if is_cflow_group((*(*ins).detail).groups[i].into()) {
                for j in 0..(*(*ins).detail).__bindgen_anon_1.x86.op_count {
                    op = &mut (*(*ins).detail).__bindgen_anon_1.x86.operands[j as usize];
                    if (*op).type_ == x86_op_type_X86_OP_IMM {
                        return Some((*op).__bindgen_anon_1.imm as u64);
                    }
                }
            }
        }
    }
    None
}

impl fmt::Display for cs_insn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut ins_str = String::new();

        unsafe {
            ins_str.push_str(&format!("0x{:013x} ", self.address));
            for i in 0..16 {
                if i < self.size as usize {
                    ins_str.push_str(&format!("{:02x}", self.bytes[i]));
                }
                else {
                    ins_str.push_str(&format!("  "));
                }
            }
            let mnemonic = CStr::from_ptr(self.mnemonic.as_ptr())
                                 .to_string_lossy();
            let op_str = CStr::from_ptr(self.op_str.as_ptr())
                               .to_string_lossy();
            ins_str.push_str(&format!(" {} {}", mnemonic, op_str));
        }

        write!(f, "{}", ins_str)
    }
}

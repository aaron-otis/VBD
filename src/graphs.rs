use binary::binary::BasicBlock;
use capstone;

pub struct CFG<'a> {
    pub start: u64,
    pub end: u64,
    pub edges: Vec<(u64, u64)>,
    pub vertices: &'a Vec<BasicBlock>
}

impl CFG<'_> {
    pub fn new(blocks: &Vec<BasicBlock>) -> CFG {
        let last_block = blocks.len() - 1;
        let last_insn = blocks[last_block].instructions.len() - 1;
        let edges = CFG::detect_edges(blocks);

        CFG {start: blocks[0].entry,
             end: blocks[last_block].instructions[last_insn].address,
             edges: edges,
             vertices: blocks
            }
    }

    fn detect_edges(blocks: &Vec<BasicBlock>) -> Vec<(u64, u64)> {
        let mut edges: Vec<(u64, u64)> = Vec::new();

        /* Determine edges by iterating through each block to find the addresses
         * the block can change control to.
         */
        for block in blocks {
            // Get last instruction in the block.
            let last_insn = block.instructions[block.instructions.len() - 1];
            let next_insn = last_insn.address + last_insn.size as u64;
            //println!("{}", last_insn);

            /* If the last instruction is a control flow changing instruction, we
             * want to add and edge from the current block to the block containing
             * the target instruction (which should be the entry to the block).
             */
            if CFG::is_cflow_ins(last_insn.id) {
                println!("found cflow ins at {:x}", last_insn.address);
                let target = capstone::get_immediate_target(&last_insn);

                // We can only handle immediate targets and fail on all others.
                match target {
                    Some(addr) => edges.push((block.entry, addr)),
                    None => (),
                };

                /* If this instruction is not an unconditional control flow changing
                 * instruction (i.e. jmp, ret, etc.), then and edge from this block to
                 * the next sequential block should be added.
                 */
                if !capstone::is_unconditional_cflow_ins(&last_insn) {
                    edges.push((block.entry, next_insn));
                }
            }
            /* If the last instruction isn't a control flow changing one, add an edge
             * to the next sequential block.
             */
            else {
                edges.push((block.entry, next_insn));
            }
        }

        edges
    }

    fn is_cflow_ins(id: u32) -> bool {
        if id == capstone::x86_insn_X86_INS_CALL ||
           id == capstone::x86_insn_X86_INS_ENTER ||
           id == capstone::x86_insn_X86_INS_INT ||
           id == capstone::x86_insn_X86_INS_INTO ||
           id == capstone::x86_insn_X86_INS_IRET ||
           id == capstone::x86_insn_X86_INS_JA ||
           id == capstone::x86_insn_X86_INS_JAE ||
           id == capstone::x86_insn_X86_INS_JB ||
           id == capstone::x86_insn_X86_INS_JBE ||
           id == capstone::x86_insn_X86_INS_JCXZ ||
           id == capstone::x86_insn_X86_INS_JE ||
           id == capstone::x86_insn_X86_INS_JECXZ ||
           id == capstone::x86_insn_X86_INS_JG ||
           id == capstone::x86_insn_X86_INS_JGE ||
           id == capstone::x86_insn_X86_INS_JL ||
           id == capstone::x86_insn_X86_INS_JLE ||
           id == capstone::x86_insn_X86_INS_JMP ||
           id == capstone::x86_insn_X86_INS_JNE ||
           id == capstone::x86_insn_X86_INS_JNO ||
           id == capstone::x86_insn_X86_INS_JNP ||
           id == capstone::x86_insn_X86_INS_JNS ||
           id == capstone::x86_insn_X86_INS_JO ||
           id == capstone::x86_insn_X86_INS_JP ||
           id == capstone::x86_insn_X86_INS_JRCXZ ||
           id == capstone::x86_insn_X86_INS_JS ||
           id == capstone::x86_insn_X86_INS_LJMP ||
           id == capstone::x86_insn_X86_INS_RETF ||
           id == capstone::x86_insn_X86_INS_RETFQ ||
           id == capstone::x86_insn_X86_INS_RET {
            return true;
        }
        false

    }
}
use std::fmt;
use std::collections::HashSet;
use binary::binary::{Binary, BasicBlock};
use binary::section::Section;
use capstone;

pub trait Vertex {
    fn get_id(&self) -> u64;
}

pub trait Graph<V: Vertex> {
    fn get_edges(&self) -> &HashSet<Edge>;
    fn add_edge(&mut self, edge: Edge) -> bool;
    fn get_vertices(&self) -> HashSet<V>;
    fn add_vertex(&mut self, vertex: V) -> bool;

    fn get_successors(&self, addr: u64) -> HashSet<Edge> {
        let mut successors: HashSet<Edge> = HashSet::new();

        for edge in self.get_edges() {
            if edge.entry == addr {
                successors.insert(edge.clone());
            }
        }

        successors
    }

    fn get_predecessors(&self, addr: u64) -> HashSet<Edge> {
        let mut predecessors: HashSet<Edge> = HashSet::new();

        for edge in self.get_edges() {
            if edge.exit == addr {
                predecessors.insert(edge.clone());
            }
        }

        predecessors
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Edge {
    pub entry: u64,
    pub exit: u64,
}

impl Edge {
    pub fn new(entry: u64, exit: u64) -> Edge {
        Edge {entry: entry, exit: exit}
    }
}

impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(0x{:x}, 0x{:x})", self.entry, self.exit)
    }
}

#[derive(Clone)]
pub struct CFG<'a> {
    pub start: u64,
    pub end: u64,
    pub edges: HashSet<Edge>,
    pub vertices: &'a Vec<BasicBlock>
}

impl CFG<'_> {
    pub fn new(bin: &Binary) -> Option<CFG> {
        let last_block = bin.blocks.len() - 1;
        let last_insn = bin.blocks[last_block].instructions.len() - 1;
        let text = match bin.clone().get_text_section() {
            Ok(sec) => sec,
            Err(_e) => return None,
        };
        let edges = CFG::detect_edges(bin.blocks.as_slice(), &text);

        Some(CFG {start: bin.blocks[0].entry,
                  end: bin.blocks[last_block].instructions[last_insn].address,
                  edges: edges,
                  vertices: &bin.blocks
                  })
    }

    pub fn get_block(&self, addr: u64) -> Option<&BasicBlock> {
        for block in self.vertices {
            if block.entry == addr {
                return Some(&block);
            }
        }
        None
    }

    fn detect_edges(blocks: &[BasicBlock], text: &Section) -> HashSet<Edge> {
        let mut edges: HashSet<Edge> = HashSet::new();

        /* Create a partial edge set.
         * Determine edges by iterating through each block to find the addresses
         * the block can change control to.
         */
        for block in blocks {
            let last_insn = &block.instructions[block.instructions.len() - 1];
            let next_insn = last_insn.address + last_insn.size as u64;

            /* If the last instruction is a control flow changing instruction, we
             * want to add and edge from the current block to the block containing
             * the target instruction (which should be the entry to the block).
             */
            if last_insn.is_cflow_ins() {
                let target = last_insn.get_immediate_target();

                // We currently can only handle immediate targets and fail on all others.
                match target {
                    Some(addr) => edges.insert(Edge::new(block.entry, addr)),
                    None => true,
                };

                /* If this instruction is not an unconditional control flow changing
                 * instruction (i.e. jmp, ret, etc.), then and edge from this block to
                 * the next sequential block should be added, if that block exists.
                 */
                if !last_insn.is_unconditional_cflow_ins() {
                    if CFG::block_exists(blocks, next_insn) {
                        edges.insert(Edge::new(block.entry, next_insn));
                    }
                }

            }
            /* If the last instruction isn't a control flow changing one, add an edge
             * to the next sequential block.
             */
            else {
                edges.insert(Edge::new(block.entry, next_insn));
            }
        }

        // Create a temporary CFG.
        let last_block = blocks.len() - 1;
        let last_insn = blocks[last_block].instructions.len() - 1;
        let cfg = CFG {start: blocks[0].entry,
                       end: blocks[last_block].instructions[last_insn].address,
                       edges: edges.clone(),
                       vertices: &blocks.to_vec().clone()};

        /* Iterate over each block and use partial edge set to resolve edges due to
         * returns.
         */
        for block in blocks {
            let last_insn = &block.instructions[block.instructions.len() - 1];
            let next_insn = last_insn.address + last_insn.size as u64;
            let mut seen: HashSet<u64> = HashSet::new();

            // Only process blocks that call functions.
            if last_insn.id == capstone::x86_insn_X86_INS_CALL &&
               !seen.contains(&block.entry) {
                let target = last_insn.get_immediate_target();

                match target {
                    Some(addr) => {
                        // Only search for returns if there is a valid return address.
                        if CFG::block_exists(blocks, next_insn) {

                            /* There are two scenarios: The target address is either
                             * inside the .text segment or not. We handle these
                             * differently.
                             */
                            if text.contains(addr) {
                                /* The target call is in the text section and we can
                                 * traverse its subgraph.
                                 */
                                let mut stack: Vec<u64> = Vec::new();
                                stack.push(next_insn);

                                for edge in CFG::ret_walk(addr, &cfg, &mut seen, stack) {
                                    edges.insert(edge);
                                }
                            }
                            else {
                                /* The target address is outside of the .text segment,
                                 * we will ignore the fact that a call occurred and
                                 * just place an edge from the calling block to the
                                 * block the function would have returned to.
                                 */
                                edges.remove(&Edge::new(block.entry, addr));
                                edges.insert(Edge::new(block.entry, next_insn));
                            }
                        }

                    },
                    // If 'target' cannot be resolved, add a pseudo fall through edge.
                    None => if CFG::block_exists(blocks, next_insn) {
                        edges.insert(Edge::new(block.entry, next_insn));
                    },
                };
            }
        }

        edges
    }

    fn block_exists(blocks: &[BasicBlock], entry: u64) -> bool {
        for block in blocks {
            if block.entry == entry {
                return true;
            }
        }
        false
    }

    fn ret_walk(addr: u64, graph: &CFG, seen: &mut HashSet<u64>,
              mut ret_stack: Vec<u64>) -> HashSet<Edge> {
        let mut new_edges: HashSet<Edge> = HashSet::new();

        // Try to get the block with entry 'addr'.
        let block = match graph.get_block(addr) {
            Some(block) => block,
            None => return new_edges,
        };

        // Base case.
        if block.returns() {
            // Ensure the stack has a value.
            match ret_stack.pop() {
                Some(ret_addr) => {
                    new_edges.insert(Edge::new(block.entry, ret_addr));
                },
                None => (),
            };
            return new_edges;
        }

        // Recursively search this block's successors.
        for edge in graph.get_successors(block.entry) {
            // Prevent infinite loops by checking if this block has been seen.
            if !seen.contains(&edge.exit) {
                seen.insert(edge.exit);

                // If the next block calls a function, push return address on the stack.
                match graph.get_block(edge.exit) {
                    Some(b) => if b.has_call() {
                        match b.instructions.last() {
                            Some(insn) => match insn.get_immediate_target() {
                                Some(target) => ret_stack.push(target),
                                None => (),
                            },
                            None => (),
                        };
                    },
                    None => (),
                };

                for new_edge in CFG::ret_walk(edge.exit, graph, seen, ret_stack.clone()) {
                    new_edges.insert(new_edge);
                }
            }
        }

        new_edges
    }
}

impl Graph<BasicBlock> for CFG<'_> {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        true
    }

    fn get_vertices(&self) -> HashSet<BasicBlock> {
        let mut vertices: HashSet<BasicBlock> = HashSet::new();

        for vertex in self.vertices {
            vertices.insert(vertex.clone());
        }

        vertices
    }

    fn add_vertex(&mut self, vertex: BasicBlock) -> bool {
        true
    }
}

pub struct DominatorTree<'a> {
    pub start: u64,
    pub vertices: &'a Vec<BasicBlock>,
    pub edges: HashSet<Edge>,
    pub cfg: CFG<'a>,
}

impl<'a> DominatorTree<'a> {
    pub fn new(cfg: CFG<'a>, start: u64) -> DominatorTree<'a> {
        let mut edges: HashSet<Edge> = HashSet::new();

        DominatorTree {start: start, vertices: cfg.vertices, edges: edges, cfg: cfg}
    }

    pub fn is_sdom(&self, x: u64, y: u64) -> bool {
        false
    }

    pub fn sdoms(&self, addr: u64) {
        //self.edges.iter().filter(|&&e| self.is_sdom(addr, e)).collect()
    }

    pub fn is_idom(&self, x: u64, y: u64) -> bool {
        false
    }

    pub fn idoms(&self, addr: u64) {
        //self.edges.iter().filter(|&&e| self.is_idom(addr, e)).collect()
    }

    pub fn from_binary(bin: &'a Binary, start: u64) -> Option<DominatorTree<'a>> {
        match bin.cfg() {
            Some(cfg) => Some(DominatorTree::new(cfg, start)),
            None => None,
        }
    }
}

impl Graph<BasicBlock> for DominatorTree<'_> {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        true
    }

    fn get_vertices(&self) -> HashSet<BasicBlock> {
        let mut vertices: HashSet<BasicBlock> = HashSet::new();

        for vertex in self.vertices {
            vertices.insert(vertex.clone());
        }

        vertices
    }

    fn add_vertex(&mut self, vertex: BasicBlock) -> bool {
        true
    }
}

pub struct DJGraph<'a> {
    pub vertices: &'a Vec<BasicBlock>,
    pub edges: HashSet<Edge>,
}

impl<'a> DJGraph<'_> {
    pub fn from_cfg(cfg: CFG<'a>, start: u64) -> DJGraph<'a> {
        let dom_tree: DominatorTree<'a> = DominatorTree::new(cfg, start);
        let mut edges = dom_tree.edges.clone();

        // Add J edges.

        DJGraph {vertices: dom_tree.vertices, edges: edges}
    }

    pub fn from_dom_tree(dom_tree: DominatorTree) -> DJGraph {
        let mut edges = dom_tree.edges.clone();

        // Add J edges.

        DJGraph {vertices: dom_tree.vertices, edges: edges}
    }
}

impl Graph<BasicBlock> for DJGraph<'_> {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        true
    }

    fn get_vertices(&self) -> HashSet<BasicBlock> {
        let mut vertices: HashSet<BasicBlock> = HashSet::new();

        for vertex in self.vertices {
            vertices.insert(vertex.clone());
        }

        vertices
    }

    fn add_vertex(&mut self, vertex: BasicBlock) -> bool {
        true
    }
}

pub fn dfs<G: Graph<BasicBlock>>(graph: G) {
}

pub fn dfs_ordering<G: Graph<BasicBlock>>(graph: G) {
}

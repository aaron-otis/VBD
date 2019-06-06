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
    fn get_vertices(&self) -> Vec<V>;
    fn add_vertex(&mut self, vertex: V) -> bool;
    fn root(&self) -> u64;

    fn get_successors(&self, addr: u64) -> Vec<u64> {
        let mut successors: Vec<u64> = Vec::new();

        for edge in self.get_edges() {
            if edge.entry == addr {
                successors.push(edge.exit.clone());
            }
        }

        successors
    }

    fn get_predecessors(&self, addr: u64) -> Vec<u64> {
        let mut predecessors: Vec<u64> = Vec::new();

        for edge in self.get_edges() {
            if edge.exit == addr {
                predecessors.push(edge.entry.clone());
            }
        }

        predecessors
    }
}

pub trait Tree {
    fn get_level(&self, addr: u64) -> u64;
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
pub struct CFG {
    pub start: u64,
    pub end: u64,
    pub edges: HashSet<Edge>,
    pub vertices: Vec<BasicBlock>
}

impl CFG {
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
                  vertices: bin.blocks.clone()
                  })
    }

    pub fn get_block(&self, addr: u64) -> Option<&BasicBlock> {
        for block in &self.vertices {
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
                       vertices: blocks.to_vec().clone()};

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
                                /*
                                let mut stack: Vec<u64> = Vec::new();
                                stack.push(next_insn);

                                for edge in CFG::ret_walk(addr, &cfg, &mut seen, stack) {
                                    edges.insert(edge);
                                }
                                */
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
}

impl Graph<BasicBlock> for CFG {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        self.edges.insert(edge)
    }

    fn get_vertices(&self) -> Vec<BasicBlock> {
        self.vertices.clone()
    }

    fn add_vertex(&mut self, vertex: BasicBlock) -> bool {
        self.vertices.push(vertex);
        true
    }

    fn root(&self) -> u64 {
        self.start
    }
}

pub struct DominatorTree {
    pub start: u64,
    pub vertices: Vec<BasicBlock>,
    pub edges: HashSet<Edge>,
    pub cfg: CFG,
}

impl DominatorTree {
    pub fn new(cfg: CFG, start: u64) -> DominatorTree {
        let mut edges: HashSet<Edge> = HashSet::new();

        // Iteratively build Dominator tree.

        DominatorTree {start: start, vertices: cfg.vertices.clone(), edges: edges,
                       cfg: cfg}
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

    pub fn from_binary(bin: &Binary, start: u64) -> Option<DominatorTree> {
        match bin.cfg() {
            Some(cfg) => Some(DominatorTree::new(cfg, start)),
            None => None,
        }
    }
}

impl Graph<BasicBlock> for DominatorTree {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        self.edges.insert(edge)
    }

    fn get_vertices(&self) -> Vec<BasicBlock> {
        self.vertices.clone()
    }

    fn add_vertex(&mut self, vertex: BasicBlock) -> bool {
        self.vertices.push(vertex);
        true
    }

    fn root(&self) -> u64 {
        self.start
    }
}

pub struct DJGraph {
    pub start: u64,
    pub vertices: Vec<BasicBlock>,
    pub edges: HashSet<Edge>,
}

impl DJGraph {
    pub fn from_cfg(cfg: CFG, start: u64) -> DJGraph {
        let dom_tree: DominatorTree = DominatorTree::new(cfg, start);
        let mut edges = dom_tree.edges.clone();

        // Add J edges.

        DJGraph {start: dom_tree.start, vertices: dom_tree.vertices, edges: edges}
    }

    pub fn from_dom_tree(dom_tree: DominatorTree) -> DJGraph {
        let mut edges = dom_tree.edges.clone();

        // Add J edges.

        DJGraph {start: dom_tree.start, vertices: dom_tree.vertices, edges: edges}
    }
}

impl Graph<BasicBlock> for DJGraph {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        self.edges.insert(edge)
    }

    fn get_vertices(&self) -> Vec<BasicBlock> {
        self.vertices.clone()
    }

    fn add_vertex(&mut self, vertex: BasicBlock) -> bool {
        self.vertices.push(vertex);
        true
    }

    fn root(&self) -> u64 {
        self.start
    }
}

type Ordering = Vec<u64>;

pub fn dfs<G: Graph<BasicBlock>>(graph: &G, root: u64,
                                 seen: &mut HashSet<u64>) -> Ordering {
    let mut order: Ordering = Vec::new();

    order.push(root);
    seen.insert(root);

    for successor in graph.get_successors(root) {
        if !seen.contains(&successor) {
            order.append(&mut dfs(graph, successor, seen));
        }
    }

    order
}

//pub fn connected_components<G: Graph<BasicBlock>>(graph: G) -> Vec<Component> {
//}

use std::fmt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::iter::FromIterator;
use binary::binary::{Binary, BasicBlock};
use binary::section::Section;
use capstone;

pub trait Vertex {
    fn get_id(&self) -> u32;
}

impl Vertex for u32 {
    fn get_id(&self) -> u32 {
        *self
    }
}

impl Vertex for (u32, EdgeSet) {
    fn get_id(&self) -> u32 {
        self.0
    }
}

pub trait Graph<V: Vertex> {
    fn get_edges(&self) -> &HashSet<Edge>;
    fn add_edge(&mut self, edge: Edge) -> bool;
    fn get_vertices(&self) -> Vec<V>;
    fn add_vertex(&mut self, vertex: V) -> bool;
    fn root(&self) -> u32;
    fn get_edgeset(&self, addr: u32) -> EdgeSet;

    fn get_successors(&self, addr: u32) -> Vec<u32> {
        self.get_edgeset(addr).successors.clone()
    }

    fn get_predecessors(&self, addr: u32) -> Vec<u32> {
        self.get_edgeset(addr).predecessors.clone()
    }
}

pub trait Tree {
    fn get_level(&self, addr: u32) -> u32;
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum EdgeType {
    Directed,
    UnDirected,
    DEdge,
    BJEdge,
    CJEdge,
    SPBack,
    SPTree,
    SPForward,
    SPCross,
}

impl fmt::Display for EdgeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            EdgeType::Directed => "Directed",
            EdgeType::UnDirected => "Undirected",
            EdgeType::DEdge => "D",
            EdgeType::BJEdge => "BJ",
            EdgeType::CJEdge => "CJ",
            EdgeType::SPBack => "sp-back",
            EdgeType::SPTree => "sp-tree",
            EdgeType::SPForward => "sp-forward",
            EdgeType::SPCross => "sp-cross",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Edge {
    pub entry: u32,
    pub exit: u32,
    pub edge_type: EdgeType,
}

impl Edge {
    pub fn new(entry: u32, exit: u32, edge_type: EdgeType) -> Edge {
        Edge {entry: entry, exit: exit, edge_type}
    }

    pub fn contains(&self, addr: u32) -> bool {
        self.entry == addr || self.exit == addr
    }

    pub fn to_type(&self, edge_type: EdgeType) -> Edge {
        Edge {entry: self.entry, exit: self.exit, edge_type: edge_type}
    }
}

impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{} edge (0x{:x}, 0x{:x})>", self.edge_type, self.entry, self.exit)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EdgeSet {
    predecessors: Vec<u32>,
    successors: Vec<u32>
}

impl EdgeSet {
    pub fn new(predecessors: &[u32], successors: &[u32]) -> EdgeSet {
        EdgeSet {predecessors: predecessors.to_vec(), successors: successors.to_vec()}
    }

    pub fn new_empty() -> EdgeSet {
        EdgeSet {predecessors: Vec::new(), successors: Vec::new()}
    }

    pub fn add_predecessor(&mut self, predecessor: u32) {
        self.predecessors.push(predecessor);
    }

    pub fn add_successor(&mut self, successor: u32) {
        self.successors.push(successor);
    }

    pub fn num_elements(&self) -> (usize, usize) {
        (self.predecessors.len(), self.successors.len())
    }
}

#[derive(Clone)]
pub struct CFG {
    pub start: u32,
    pub end: u32,
    pub edges: HashSet<Edge>,
    pub vertices: HashMap<u32, EdgeSet>
}

impl CFG {
    pub fn new(bin: &Binary) -> Option<CFG> {
        let last_block = bin.blocks.len() - 1;
        let text = match bin.clone().get_text_section() {
            Ok(sec) => sec,
            Err(_e) => return None,
        };
        let edges = CFG::detect_edges(bin.blocks.as_slice(), &text);
        let mut vertices: HashMap<u32, EdgeSet> = HashMap::new();

        // Add all vertices as keys, each with an empty EdgeSets.
        for block in &bin.blocks {
            vertices.insert(block.entry as u32, EdgeSet::new_empty());
        }
        // Iteratively update EdgeSets.
        for edge in &edges {
            // Add successor.
            if let Some(edgeset) = vertices.get_mut(&edge.entry) {
                edgeset.add_successor(edge.exit);
            }
            // Add predecessor.
            if let Some(edgeset) = vertices.get_mut(&edge.exit) {
                edgeset.add_predecessor(edge.entry);
            }
        }

        Some(CFG {start: bin.blocks[0].entry as u32,
                  end: bin.blocks[last_block].entry as u32,
                  edges: edges,
                  vertices: vertices
                  })
    }

    /*
    pub fn get_block(&self, addr: u64) -> Option<&BasicBlock> {
        for block in &self.vertices {
            if block.entry == addr {
                return Some(&block);
            }
        }
        None
    }
    */

    /** Returns a subgraph of the current graph rooted at 'root'.
     *
     * Warning: May not return a connected component!
     */
    /*
    pub fn subgraph(&self, root: u64) -> CFG {
        let order = dfs(self, root, &mut HashSet::new(), 0);
        let vertices = self.vertices.iter()
                                    .filter(|&(k, v)| order.order
                                                           .contains_key(k))
                                    .map(|(&k, &v)| (k, v)) // Need map to collect.
                                    .collect();
        let edges = self.edges.iter()
                              .filter(|e| order.order.contains_key(&e.entry) ||
                                          order.order.contains_key(&e.exit))
                              .cloned()
                              .collect();

        CFG {start: root, end: 0, edges: edges, vertices: vertices}
    }
    */

    pub fn components(&self) -> Vec<CFG> {
        let mut components: Vec<CFG> = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<u32> = VecDeque::new();

        println!("This CFG has {} vertices and {} edges\n", self.vertices.len(), self.edges.len());

        for vertex in self.vertices.keys() {
            if !seen.contains(vertex) {
                seen.insert(*vertex);
                queue.push_back(*vertex);

                let mut vertices: HashMap<u32, EdgeSet> = HashMap::new();
                while let Some(v) = queue.pop_front() {
                    let mut edgeset = EdgeSet::new_empty();

                    for successor in self.get_successors(v) {
                        if !seen.contains(&successor) {
                            seen.insert(successor);
                            queue.push_back(successor);
                        }
                        edgeset.add_successor(successor);
                    }
                    for predecessor in self.get_predecessors(v) {
                        if !seen.contains(&predecessor) {
                            seen.insert(predecessor);
                            queue.push_back(predecessor);
                        }
                        edgeset.add_predecessor(predecessor);
                    }
                    vertices.insert(v, edgeset);
                }
                println!("found {} vertices", vertices.len());
                let edges = self.edges.iter()
                                      .filter(|e| vertices.contains_key(&e.entry) ||
                                                  vertices.contains_key(&e.exit))
                                      .cloned()
                                      .collect::<HashSet<_>>();
                println!("Found {} edges", edges.len());
                components.push(CFG {start: self.find_root(vertices.keys()
                                                                   .cloned()
                                                                   .collect::<Vec<_>>()
                                                                   .as_slice(),
                                                           &edges),
                                     end: 0,
                                     vertices: vertices,
                                     edges: edges});
            }
        }

        components
    }

    fn detect_edges(blocks: &[BasicBlock], text: &Section) -> HashSet<Edge> {
        let mut edges: HashSet<Edge> = HashSet::new();

        /* Create a partial edge set.
         * Determine edges by iterating through each block to find the addresses
         * the block can change control to.
         */
        for block in blocks {
            let last_insn = &block.instructions[block.instructions.len() - 1];
            let next_insn = (last_insn.address + last_insn.size as u64) as u32;

            /* If the last instruction is a control flow changing instruction, we
             * want to add and edge from the current block to the block containing
             * the target instruction (which should be the entry to the block).
             */
            if last_insn.is_cflow_ins() {
                let target = last_insn.get_immediate_target();

                // We currently can only handle immediate targets and fail on all others.
                match target {
                    Some(addr) => edges.insert(Edge::new(block.entry as u32,
                                                         addr as u32,
                                                         EdgeType::Directed)),
                    None => true,
                };

                /* If this instruction is not an unconditional control flow changing
                 * instruction (i.e. jmp, ret, etc.), then and edge from this block to
                 * the next sequential block should be added, if that block exists.
                 */
                if !last_insn.is_unconditional_cflow_ins() {
                    if CFG::block_exists(blocks, next_insn) {
                        edges.insert(Edge::new(block.entry as u32, next_insn,
                                               EdgeType::Directed));
                    }
                }

            }
            /* If the last instruction isn't a control flow changing one, add an edge
             * to the next sequential block.
             */
            else {
                edges.insert(Edge::new(block.entry as u32,
                                       next_insn,
                                       EdgeType::Directed));
            }
        }

        // Create a temporary CFG.
        let last_block = blocks.len() - 1;
        let last_insn = blocks[last_block].instructions.len() - 1;
        /*
        let cfg = CFG {start: blocks[0].entry,
                       end: blocks[last_block].instructions[last_insn].address,
                       edges: edges.clone(),
                       vertices: blocks.to_vec().clone()};
         */

        /* Iterate over each block and use partial edge set to resolve edges due to
         * returns.
         */
        for block in blocks {
            let last_insn = &block.instructions[block.instructions.len() - 1];
            let next_insn = (last_insn.address + last_insn.size as u64) as u32;
            let mut seen: HashSet<u32> = HashSet::new();

            // Only process blocks that call functions.
            if last_insn.id == capstone::x86_insn_X86_INS_CALL &&
               !seen.contains(&(block.entry as u32)) {
                let target = last_insn.get_immediate_target();

                match target {
                    Some(addr) => {
                        // Only search for returns if there is a valid return address.
                        if CFG::block_exists(blocks, next_insn) {

                            /* There are two scenarios: The target address is either
                             * inside the .text segment or not. We handle these
                             * differently.
                             */
                            if !text.contains(addr) {
                                /* The target address is outside of the .text segment,
                                 * we will ignore the fact that a call occurred and
                                 * just place an edge from the calling block to the
                                 * block the function would have returned to.
                                 */
                                edges.remove(&Edge::new(block.entry as u32,
                                                        addr as u32,
                                                        EdgeType::Directed));
                                edges.insert(Edge::new(block.entry as u32, next_insn,
                                                       EdgeType::Directed));
                            }
                        }

                    },
                    // If 'target' cannot be resolved, add a pseudo fall through edge.
                    None => if CFG::block_exists(blocks, next_insn) {
                        edges.insert(Edge::new(block.entry as u32, next_insn,
                                               EdgeType::Directed));
                    },
                };
            }
        }

        edges
    }

    fn find_root(&self, vertices: &[u32], edges: &HashSet<Edge>) -> u32 {
        if vertices.len() == 1 {
            return vertices[0];
        }
        for vertex in vertices {
            if self.get_predecessors(*vertex).is_empty() {
                return *vertex;
            }
        }
        // FIXME: Return a better value here!
        vertices[0]
    }

    fn block_exists(blocks: &[BasicBlock], entry: u32) -> bool {
        for block in blocks {
            if block.entry == entry as u64 {
                return true;
            }
        }
        false
    }
}

impl fmt::Display for CFG {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "<CFG start: 0x{:x}, vertices: [{}], edges: [{}]>",
               self.start,
               &self.vertices.keys()
                             .map(|v| format!("0x{:x}", v))
                             .collect::<Vec<String>>()
                             .join(", "),
               &self.edges.iter()
                          .map(|e| format!("{}", e))
                          .collect::<Vec<String>>()
                          .join(", "))
    }
}

impl Graph<u32> for CFG {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        self.edges.insert(edge)
    }

    fn get_vertices(&self) -> Vec<u32> {
        self.vertices.keys().cloned().collect::<Vec<_>>()
    }

    fn add_vertex(&mut self, vertex: u32) -> bool {
        false
    }

    fn root(&self) -> u32 {
        self.start
    }

    fn get_edgeset(&self, addr: u32) -> EdgeSet {
        match self.vertices.get(&addr) {
            Some(edgeset) => edgeset.clone(),
            None => EdgeSet::new_empty()
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DominatorVertex {
    pub level: u32,
    pub edgeset: EdgeSet,
    pub dominators: HashSet<u32>,
}

impl DominatorVertex {
    pub fn new(edgeset: EdgeSet, level: u32, dominators: HashSet<u32>) -> DominatorVertex {
        DominatorVertex {level: level,
                         edgeset: edgeset,
                         dominators: dominators}
    }

    pub fn new_empty(level: u32) -> DominatorVertex {
        DominatorVertex {level: level,
                         edgeset: EdgeSet::new_empty(),
                         dominators: HashSet::new()}
    }
}

/*
impl DominatorVertex<BasicBlock> {
    pub fn new(block: BasicBlock, level: u64) -> DominatorVertex<BasicBlock> {
        DominatorVertex {level: level, vertex: block}
    }
}

impl Vertex for DominatorVertex<BasicBlock> {
    fn get_id(&self) -> u64 {
        self.vertex.entry
    }
}

impl Vertex for DominatorVertex<(u64, EdgeSet)> {
    fn get_id(&self) -> u64 {
        self.vertex.0
    }
}

impl fmt::Display for DominatorVertex<BasicBlock> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Vertex 0x{:x} @ level {}>", self.vertex.entry, self.level)
    }
}
*/

#[derive(Clone)]
pub struct DominatorTree {
    pub root: u32,
    pub max_level: u32,
    pub vertices: HashMap<u32, DominatorVertex>,
    pub edges: HashSet<Edge>,
    pub cfg: CFG,
}

impl DominatorTree {
    /* Requires 'cfg' to be connected! */
    pub fn new(cfg: &CFG, start: u32) -> DominatorTree {
        let block_entries: Vec<u32> = cfg.vertices
                                         .keys()
                                         .cloned()
                                         .collect();

        // Initialize Dom[s] = {s} and Dom[v] = V for v in V - {s}.
        let mut dominators: HashMap<u32, HashSet<u32>> = HashMap::new();
        let mut start_dom: HashSet<u32> = HashSet::new();
        start_dom.insert(start);
        dominators.insert(start, start_dom);
        println!("[DominatorTree::new] Initializing dominators hashmap");
        for vertex in cfg.vertices.keys() {
            if *vertex != start {
                dominators.insert(*vertex,
                                  HashSet::from_iter(block_entries.iter().cloned()));
            }
        }
        /* Iteratively build Dominator tree.
         */
        let mut updated_dominators = true;
        println!("[DominatorTree::new] Finding all dominators");
        while updated_dominators {
            updated_dominators = false;

            for vertex in &block_entries {
                let mut dom_set: HashSet<u32> = HashSet::new();
                dom_set.insert(*vertex);

                let mut intersect: HashSet<u32> = HashSet::new();
                for predecessor in cfg.get_predecessors(*vertex) {
                    if intersect.is_empty() {
                        intersect = dominators[&predecessor].clone();
                    }
                    else {
                        intersect = intersect.intersection(&dominators[&predecessor])
                                             .cloned()
                                             .collect();
                    }
                }

                dom_set = dom_set.union(&intersect).cloned().collect();

                /* FIXME: Hack to get blocks without predecessors and not the start
                 * vertex to work without eliminating the start vertex as a dominator.
                 */
                if !dom_set.contains(&start) {
                    dom_set.insert(start);
                }
                if dom_set != dominators[&vertex] {
                    updated_dominators = true;
                    match dominators.get_mut(vertex) {
                        Some(set) => *set = dom_set,
                        _ => panic!("Did not find block entry 0x{:x}.", *vertex),
                    };
                }
            }
        }

        // Create set of DominatorVertex to preserve level information.
        let mut dom_vertices: HashMap<u32, DominatorVertex> = HashMap::new();
        let mut max_level: u32 = 0;

        // Store idoms so we don't have to calculate them twice.
        let mut idoms: HashMap<u32, u32> = HashMap::new();

        // Add each (idom(x), x) edge.
        let mut edges: HashSet<Edge> = HashSet::new();
        println!("[DominatorTree::new] Creating edge set");
        for addr in block_entries {
            if addr != start {
                let idom = DominatorTree::idom(addr, &dominators);
                edges.insert(Edge::new(idom, addr, EdgeType::DEdge));
                idoms.insert(addr, idom);
            }
        }

        /*
        let mut seen: HashSet<u64> = HashSet::new();
        seen.insert(start);
        */

        let mut queue: VecDeque<(u32, u32)> = VecDeque::new();
        queue.push_back((start, 0));
        println!("[DominatorTree::new] Creating vertex set");
        while !queue.is_empty() {
            let (vertex, level) = match queue.pop_front() {
                Some((vertex, level)) => (vertex, level),
                None => panic!("Pop failed from nonempty queue")
            };

            if level > max_level {
                max_level = level;
            }

            let mut edgeset = EdgeSet::new_empty();

            // Not all vertices have predecessors, so check the idoms HashMap.
            if let Some(&idom) = idoms.get(&vertex) {
                edgeset.add_predecessor(idom);
            }

            /* Iterate through all D edges that originate from this vertex and add
             * them to the queue.
             */
            for edge in edges.iter()
                             .filter(|&e| e.edge_type == EdgeType::DEdge &&
                                          e.entry == vertex)
                             .cloned()
                             .collect::<Vec<_>>() {
                queue.push_back((edge.exit, level + 1));
                edgeset.add_successor(edge.exit);
            }

            // Add a queue item to the DominatorVertex set.
            dom_vertices.insert(vertex,
                                DominatorVertex::new(edgeset,
                                                     level,
                                                     dominators[&vertex].clone()));
        }

        assert_eq!(cfg.vertices.len(), dom_vertices.len());

        println!("[DominatorTree::new] Done");
        DominatorTree {root: start,
                       max_level: max_level,
                       vertices: dom_vertices,
                       edges: edges,
                       cfg: cfg.clone()}
    }

    /** Returns the immediate dominator of 'vertex'.
     */
    fn idom(vertex: u32, dominators: &HashMap<u32, HashSet<u32>>) -> u32 {
        let sdoms: HashSet<u32> = dominators[&vertex].iter()
                                                     .filter(|&&d| d != vertex)
                                                     .cloned()
                                                     .collect();
        for dom in &sdoms {
            if dominators[dom] == sdoms {
                return *dom;
            }
        }

        panic!("Could not find immediate dominator for 0x{:x}", vertex);
    }

    /* Returns true if x = idom(y) and false otherwise. */
    pub fn is_idom(&self, x: u32, y: u32) -> bool {
        self.edges.contains(&Edge::new(x, y, EdgeType::DEdge))
    }

    pub fn dominates(&self, x: u32, y: u32) -> bool {
        //self.vertices[&y].dominators.contains(&x)
        match self.vertices.get(&y) {
            Some(vertex) => vertex.dominators.contains(&x),
            None => {
                // FIXME: This is likely caused by an incomplete vertex set!
                println!("0x{:x} was not found in the vertex set!", y);
                false
            }
        }
    }

    pub fn from_binary(bin: &Binary, start: u32) -> Option<DominatorTree> {
        match bin.cfg() {
            Some(cfg) => Some(DominatorTree::new(&cfg, start)),
            None => None,
        }
    }
}

impl Graph<u32> for DominatorTree {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        self.edges.insert(edge)
    }

    fn get_vertices(&self) -> Vec<u32> {
        self.vertices.keys().cloned().collect()
    }

    fn add_vertex(&mut self, vertex: u32) -> bool {
        false
    }

    fn root(&self) -> u32 {
        self.root
    }

    fn get_edgeset(&self, addr: u32) -> EdgeSet {
        match self.vertices.get(&addr) {
            Some(domset) => domset.edgeset.clone(),
            None => EdgeSet::new_empty()
        }
    }
}

pub struct DJGraph {
    pub start: u32,
    pub max_level: u32,
    pub vertices: HashMap<u32, DominatorVertex>,
    pub edges: HashSet<Edge>,
}

impl DJGraph {
    pub fn new(cfg: &CFG, start: u32) -> DJGraph {
        println!("[DJGraph::new] Creating dominator tree on CFG with {} vertices and {} edges",
                 cfg.vertices.len(),
                 cfg.edges.len());
        let dom_tree: DominatorTree = DominatorTree::new(&cfg, start);
        println!("[DJGraph::new] cloning dominator tree edges");
        let mut edges = dom_tree.edges.clone();

        println!("[DJGraph::new] Adding J edges");
        // Add J edges.
        for edge in &cfg.edges {
            // Ignore D edges.
            if !edges.contains(&Edge::new(edge.entry, edge.exit, EdgeType::DEdge)) {
                // A BJ edge is a J edge (x, y) where y dom x.
                if dom_tree.dominates(edge.exit, edge.entry) {
                    edges.insert(Edge::new(edge.entry, edge.exit, EdgeType::BJEdge));
                }
                // All other J edges are CJ edges.
                else {
                    edges.insert(Edge::new(edge.entry, edge.exit, EdgeType::CJEdge));
                }
            }
        }

        DJGraph {start: dom_tree.root, max_level: dom_tree.max_level,
                 vertices: dom_tree.vertices, edges: edges}
    }

    /* Uses the method by Sreedhar, et al. to discover loops.
     */
    pub fn detect_loops(&mut self) -> Vec<Loop> {
        let mut loops: Vec<Loop> = Vec::new();
        println!("[DJGraph::detect_loops] Detecting loops");

        // Need to identify sp-back edges from a spanning tree created via DFS.
        let ordering = dfs(self, self.start, &mut HashSet::new(), 0);
        let mut st = SpanningTree::new(ordering, &self.edges);
        let mut sp_back_edges = st.get_edges_of_type(EdgeType::SPBack);

        // Group vertices by level, from lowest to highest, and store in a vector.
        let mut levels: Vec<Vec<u32>> = Vec::new();
        for level in (0..self.max_level + 1).rev() {
            levels.push(self.vertices.iter()
                                     .filter(|&(k, v)| v.level == level)
                                     .map(|(&k, _)| k)
                                     .collect::<Vec<_>>())
        }
        for (level, vertices) in levels.iter().enumerate() {
            let mut irreducible_loop = false;
            for vertex in vertices {

                // Get call incoming edges (m_i, vertex).
                for edge in self.edges.clone()
                                      .iter()
                                      .filter(|e| e.exit == *vertex)
                                      .collect::<HashSet<_>>() {
                    /* Reducible and irreducible loops can be identified by the type
                     * of edges discovered.
                     */
                    match edge.edge_type {
                        // CJ edges identify possible irreducible loops.
                        EdgeType::CJEdge => {
                            let e = Edge::new(edge.entry, edge.exit, EdgeType::SPBack);
                            if sp_back_edges.contains(&e) {
                                irreducible_loop = true;
                            }
                        },
                        // BJ edges identify reducible loops.
                        EdgeType::BJEdge => {
                            let body = self.reach_under(edge.entry,
                                                        edge.exit,
                                                        level as u32);
                            self.collapse_vertices(body.as_slice(), *vertex);
                            loops.push(Loop {entry: *vertex, body: body});
                        },
                        _ => ()
                    };
                }
                if irreducible_loop {
                    let mut params = SCCParam::new(&self.edges);
                    strongly_connected_components(*vertex, &mut params);

                    let body = params.get_component_as_vec(*vertex);
                    match body.first() {
                        Some(&first) => {
                            self.collapse_vertices(body.as_slice(), first);
                            st.collapse_vertices(body.as_slice(), first);
                            loops.push(Loop {entry: first, body: body});
                            sp_back_edges = st.get_edges_of_type(EdgeType::SPBack);
                        },
                        None => panic!("SCC returned a zero length body!")
                    };
                }
            }
        }

        loops
    }

    pub fn collapse_vertices(&mut self, vertices: &[u32], to_vertex: u32) {
        let edges = self.edges.iter()
                              .filter(|e| vertices.contains(&e.entry) ||
                                          vertices.contains(&e.exit))
                              .cloned()
                              .collect::<HashSet<_>>();
        let mut new_edges: HashSet<Edge> = HashSet::new();

        for edge in edges {
            /* Edges that originate from inside this set of vertices, but exit
             * elsewhere will be converted to an edge from the collapsed vertex to
             * exiting vertices.
             */
            if vertices.contains(&edge.entry) && !vertices.contains(&edge.exit) &&
               to_vertex != edge.exit {
                new_edges.insert(Edge::new(to_vertex, edge.exit, edge.edge_type.clone()));
            }
            /* Edges originating outside this set to a vertex within this set will now
             * end at the collapsed vertex.
             */
            else if !vertices.contains(&edge.entry) && vertices.contains(&edge.exit) &&
                    to_vertex != edge.entry {
                new_edges.insert(Edge::new(edge.entry, to_vertex, edge.edge_type.clone()));
            }
            // Note: Edges from and to vertices within the set are dropped.

            // Each one of these edges must be removed.
            self.edges.remove(&edge);
        }
        // Add new edges and remove collapsed vertices.
        for edge in new_edges {
            self.edges.insert(edge);
        }
        self.vertices = self.vertices.iter()
                                     .filter(|&(k, _)| *k == to_vertex ||
                                                       !vertices.contains(&k))
                                     .map(|(&k, v)| (k, v.clone()))
                                     .collect::<HashMap<_, _>>();
    }

    /** Finds all vertices on equal or higher valued levels that can reach vertex x
     * without passing through vertex y.
     */
    fn reach_under(&self, x: u32, y: u32, level: u32) -> Vec<u32> {
        let mut vertices: Vec<u32> = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();

        vertices.push(x);
        for (vertex, domset) in self.vertices.iter()
                                             .filter(|&(k, v)| v.level >= level &&
                                                               *k != y)
                                             .map(|(&k, v)| (k, v.clone()))
                                             .collect::<HashMap<_, _>>() {
            if let Some(path) = self.path(vertex, x, level, &mut seen) {
                if !path.contains(&y) {
                    vertices.push(vertex);
                }
            }
        }

        vertices
    }

    pub fn path(&self, origin: u32, destination: u32, level: u32,
                seen: &mut HashSet<u32>) -> Option<Vec<u32>> {
        seen.insert(origin);
        for edge in self.edges.iter()
                              .filter(|e| e.entry == origin && !seen.contains(&e.exit))
                              .collect::<HashSet<_>>() {
            if let Some(v) = self.vertex_at(edge.exit) {
                if edge.exit == destination && v.level >= level {
                    return Some(vec![origin, destination]);
                }
            }
            match self.path(edge.exit, destination, level, seen) {
                Some(mut v) => {
                    let mut ret: Vec<u32> = vec![origin];
                    ret.append(&mut v);
                    return Some(ret);
                }
                None => (),
            };
        }

        None
    }

    pub fn vertex_at(&self, addr: u32) -> Option<DominatorVertex> {
        for (vertex, domset) in &self.vertices {
            if *vertex == addr {
                return Some(domset.clone());
            }
        }
        None
    }

    /*
    pub fn vertices_at_level(&self, level: u64) -> HashSet<u64> {
        let mut intermediate_vertices: VecDeque<u64> = VecDeque::new();

        intermediate_vertices.push_back(self.start);
        for _i in 1..level - 1 {
            let mut temp_queue: VecDeque<u64> = VecDeque::new();
            while !intermediate_vertices.is_empty() {
                match intermediate_vertices.pop_front() {
                    Some(vertex) => {
                        for successor in self.get_successors(vertex) {
                            temp_queue.push_back(successor);
                        }
                    },
                    None => (),
                };
            }
            intermediate_vertices.append(&mut temp_queue);
        }

        HashSet::from_iter(intermediate_vertices.iter().cloned())
    }
    */
}

impl Graph<u32> for DJGraph {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        self.edges.insert(edge)
    }

    fn get_vertices(&self) -> Vec<u32> {
        self.vertices.keys().cloned().collect()
    }

    fn add_vertex(&mut self, vertex: u32) -> bool {
        false
    }

    fn root(&self) -> u32 {
        self.start
    }

    fn get_edgeset(&self, addr: u32) -> EdgeSet {
        match self.vertices.get(&addr) {
            Some(domset) => domset.edgeset.clone(),
            None => EdgeSet::new_empty()
        }
    }
}

pub struct SpanningTree {
    vertices: Vec<u32>,
    edges: HashSet<Edge>
}

/**
 * A spanning tree used to discover sp-back edges.
 */
impl SpanningTree {
    pub fn new(order: Ordering, edges: &HashSet<Edge>) -> SpanningTree {
        // Clone sp-tree edges found from DFS.
        let mut sp_edges: HashSet<Edge> = order.edges.clone();

        // Determine the type of each edge (x, y).
        for edge in edges.iter()
                         .filter(|e| !sp_edges.contains(&e.to_type(EdgeType::SPTree)))
                         .collect::<HashSet<_>>() {
            // If x = y, then this is an sp-back edge.
            if edge.entry == edge.exit {
                sp_edges.insert(Edge::new(edge.entry, edge.exit, EdgeType::SPBack));
            }
            // If a path along sp-tree edges from y to x exists, this is an sp-back edge.
            match SpanningTree::path(edge.exit, edge.entry, &order.edges) {
                Some(_) => sp_edges.insert(Edge::new(edge.entry,
                                                     edge.exit,
                                                     EdgeType::SPBack)),
                None => match SpanningTree::path(edge.entry, edge.exit, &order.edges) {
                    /* If a path along sp-tree edges from x to y exists, this is an
                     * sp-forward edge.
                     */
                    Some(_) => sp_edges.insert(Edge::new(edge.entry,
                                                         edge.exit,
                                                         EdgeType::SPForward)),
                    // If no path exists in either direction, this is an sp-cross edge.
                    None => sp_edges.insert(Edge::new(edge.entry,
                                                      edge.exit,
                                                      EdgeType::SPCross)),
                }
            };
        }

        SpanningTree {vertices: Vec::from_iter(order.order.keys().cloned()),
                      edges: sp_edges}
    }

    pub fn get_edges_of_type(&self, edge_type: EdgeType) -> HashSet<Edge> {
        self.edges.iter().filter(|v| v.edge_type == edge_type).cloned().collect()
    }

    pub fn path_to(&self, origin: u32, destination: u32) -> Option<Vec<u32>> {
        SpanningTree::path(origin,
                           destination,
                           &self.edges.iter()
                                      .filter(|e| e.edge_type == EdgeType::SPTree)
                                      .cloned()
                                      .collect::<HashSet<_>>())
    }

    pub fn collapse_vertices(&mut self, vertices: &[u32], to_vertex: u32) {
        let edges = self.edges.iter()
                              .filter(|e| vertices.contains(&e.entry) ||
                                          vertices.contains(&e.exit))
                              .cloned()
                              .collect::<HashSet<_>>();
        let mut new_edges: HashSet<Edge> = HashSet::new();

        for edge in edges {
            /* Edges that originate from inside this set of vertices, but exit
             * elsewhere will be converted to an edge from the collapsed vertex to
             * exiting vertices.
             */
            if vertices.contains(&edge.entry) && !vertices.contains(&edge.exit) &&
               to_vertex != edge.exit {
                new_edges.insert(Edge::new(to_vertex, edge.exit, edge.edge_type.clone()));
            }
            /* Edges originating outside this set to a vertex within this set will now
             * end at the collapsed vertex.
             */
            else if !vertices.contains(&edge.entry) && vertices.contains(&edge.exit) &&
                    to_vertex != edge.entry {
                new_edges.insert(Edge::new(edge.entry, to_vertex, edge.edge_type.clone()));
            }
            // Note: Edges from and to vertices within the set are dropped.

            // Each one of these edges must be removed.
            self.edges.remove(&edge);
        }
        // Add new edges and remove collapsed vertices.
        for edge in new_edges {
            self.edges.insert(edge);
        }
        self.vertices = self.vertices.iter()
                                     .filter(|&&v| v == to_vertex ||
                                                 !vertices.contains(&v))
                                     .cloned()
                                     .collect::<Vec<_>>();
    }

    fn path(origin: u32, destination: u32, tree_edges: &HashSet<Edge>)
            -> Option<Vec<u32>> {
        for edge in tree_edges.iter()
                              .filter(|e| e.entry == origin)
                              .collect::<HashSet<_>>() {
            if edge.exit == destination {
                return Some(vec![origin, destination]);
            }
            match SpanningTree::path(edge.exit, destination, tree_edges) {
                Some(mut v) => {
                    let mut ret: Vec<u32> = vec![origin];
                    ret.append(&mut v);
                    return Some(ret);
                }
                None => (),
            };
        }

        None
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ordering {
    order: HashMap<u32, u32>,
    edges: HashSet<Edge>
}

impl Ordering {
    pub fn new() -> Ordering {
        Ordering {order: HashMap::new(), edges: HashSet::new()}
    }

    pub fn append(&mut self, other: Ordering) -> bool {
        self.edges = self.edges.union(&other.edges).cloned().collect();
        self.order.extend(other.order);
        true
    }
}

pub fn dfs<G: Graph<u32>>(graph: &G, root: u32, seen: &mut HashSet<u32>,
                                     depth: u32) -> Ordering {
    let mut order: Ordering = Ordering::new();

    order.order.insert(root, depth);
    seen.insert(root);

    for successor in graph.get_successors(root) {
        if !seen.contains(&successor) {
            order.edges.insert(Edge::new(root, successor, EdgeType::SPTree));
            order.append(dfs(graph, successor, seen, depth + 1));
        }
    }

    order
}

/*
pub fn connected_components<G: Graph<(u64, EdgeSet)>>(graph: &G) -> Vec<Ordering> {
    let mut components: Vec<Ordering> = Vec::new();
    let mut vertices: HashSet<u64> = HashSet::from_iter(graph.get_vertices()
                                                              .iter()
                                                              .cloned());

    while !vertices.is_empty() {
        for vertex in &vertices {
            /* If this vertex has no predecessors, treat it as a starting point and
             * get the subgraph.
             */
            if graph.get_predecessors(vertex).is_empty() {
                components.push(dfs(graph, vertex, &mut HashSet::new(), 0));
                break;
            }
        }

        if let Some(order) = components.last() {
            for addr in order.order.keys() {
                match graph.get_vertices()
                           .iter()
                           .position(|b| b.entry == *addr) {
                    Some(i) => vertices.remove(&graph.get_vertices()[i]),
                    None => false
                };
            }
        }
    }
    components
}
*/

pub struct SCCParam {
    pub edges: HashSet<Edge>,
    pub seen: HashSet<u32>,
    pub stack: Vec<u32>,
    pub vertices: HashMap<u32, SCCValue>
}

impl SCCParam {
    pub fn new(edges: &HashSet<Edge>) -> SCCParam {
        SCCParam {edges: edges.clone(),
                  seen: HashSet::new(),
                  stack: Vec::new(),
                  vertices: HashMap::new()}
    }

    pub fn get_component(&self, root: u32) -> HashSet<u32> {
        let mut component: HashSet<u32> = HashSet::new();

        for (vertex, val) in &self.vertices {
            if val.root == root && val.in_component {
                component.insert(*vertex);
            }
        }

        component
    }

    pub fn get_component_as_vec(&self, root: u32) -> Vec<u32> {
        Vec::from_iter(self.get_component(root).iter().cloned())
    }

    pub fn insert(&mut self, vertex: u32, root: u32, in_component: bool) {
        self.vertices.insert(vertex, SCCValue {root: root,
                                               in_component: in_component});
    }

    pub fn update(&mut self, vertex: &u32, root: Option<u32>,
                  in_component: Option<bool>) {
        match self.vertices.get_mut(vertex) {
            Some(val) => {
                match root {
                    Some(root) => val.root = root,
                    None => ()
                };
                match in_component {
                    Some(in_component) => val.in_component = in_component,
                    None => ()
                };
            },
            None => panic!("[SCCParam::update] Vertex 0x{:x} not in hash map", *vertex)
        };
    }

    pub fn is_in_component(&self, vertex: u32) -> bool {
        match self.vertices.get(&vertex) {
            Some(val) => return val.in_component,
            None => panic!("[SCCParam::is_in_component] vertex 0x{:x} not in hash map!",
                           vertex)
        }
    }

    /** Find the value that was processed first by checking each position on the stack.
     */
    pub fn min(&self, x: u32, y: u32) -> u32 {
        match self.stack.iter().position(|&p| p == x) {
            Some(i) => match self.stack.iter().position(|&p| p == y) {
                Some(j) => {
                    if i < j {
                        return x;
                    }
                    return y;
                },
                None => panic!("[SCCParam::min (y)] 0x{:x} not on stack!", y)
            },
            None => panic!("[SCCParam::min (x)] 0x{:x} not on stack!", x)
        };
    }

    pub fn min_of_roots(&self, x: u32, y: u32) -> u32 {
        match self.vertices.get(&x) {
            Some(x_val) => match self.vertices.get(&y) {
                Some(y_val) => self.min(x_val.root, y_val.root),
                None => panic!("[SCCParam::min_of_roots] Vertex 0x{:x} not in hash map",
                               y)
            },
            None => panic!("[SCCParam::min_of_roots] Vertex 0x{:x} not in hash map", x)
        }
    }
}

pub struct SCCValue {
    pub root: u32,
    pub in_component: bool
}

/** An implementation of Tarjan's Strongly Connected Component algorithm.
 */
pub fn strongly_connected_components(vertex: u32, params: &mut SCCParam) {
    params.seen.insert(vertex);
    params.stack.push(vertex);
    params.insert(vertex, vertex, false);

    // Check each vertex w such that (v, w) is in E.
    for edge in &params.edges.iter()
                             .filter(|e| e.entry == vertex)
                             .cloned()
                             .collect::<HashSet<_>>() {
        // Recursively traverse unseen vertices. This will modify 'params'.
        if !params.seen.contains(&edge.exit) {
            strongly_connected_components(edge.exit, params);
        }
        // When InComponent[w] = false, set root[v] = min{roo[v], root[w]}.
        if !params.is_in_component(edge.exit) {
            params.update(&vertex, Some(params.min_of_roots(vertex, edge.exit)), None);
        }
    }
    /* If root[v] = v, pop each vertex w off the stack and set in InComponent[w] = true
     * until w = v.
     */
    match params.vertices.get(&vertex) {
        Some(val) => if val.root == vertex {
            while let Some(w) = params.stack.pop() {
                params.update(&w, None, Some(true));
                if w == vertex {
                    break;
                }
            }
        },
        None => panic!("[SCC] Vertex 0x{:x} not in hash map!", vertex)
    };
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Loop {
    pub entry: u32,
    pub body: Vec<u32>
}

impl fmt::Display for Loop {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Loop @ 0x{:x} [{}]>", self.entry, self.body
                                                          .iter()
                                                          .map(|x| format!("0x{:x}", x))
                                                          .collect::<Vec<String>>()
                                                          .join(", "))
    }
}

#[test]
fn scc_test() {
    let mut edges: HashSet<Edge> = HashSet::new();

    for e in [Edge::new(1, 2, EdgeType::Directed),
              Edge::new(2, 3, EdgeType::Directed),
              Edge::new(3, 4, EdgeType::Directed),
              Edge::new(4, 5, EdgeType::Directed),
              Edge::new(5, 2, EdgeType::Directed),
              Edge::new(1, 6, EdgeType::Directed),
              Edge::new(6, 7, EdgeType::Directed),
              Edge::new(7, 6, EdgeType::Directed),
              Edge::new(7, 8, EdgeType::Directed),
              Edge::new(5, 8, EdgeType::Directed),
                ].iter() {
        edges.insert((*e).clone());
    }

    let mut test = HashSet::from_iter(vec![2, 3, 4, 5].iter().cloned());
    let mut params = SCCParam::new(&edges);
    strongly_connected_components(2, &mut params);

    let mut body = params.get_component(2);
    assert_eq!(body, test);

    params = SCCParam::new(&edges);
    strongly_connected_components(1, &mut params);
    body = params.get_component(1);
    test = HashSet::from_iter(vec![1].iter().cloned());
    assert_eq!(body, test);

    params = SCCParam::new(&edges);
    strongly_connected_components(6, &mut params);
    test = HashSet::from_iter(vec![6, 7].iter().cloned());
    body = params.get_component(6);
    assert_eq!(body, test);
}

use std::fmt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::iter::FromIterator;
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
    pub entry: u64,
    pub exit: u64,
    pub edge_type: EdgeType,
}

impl Edge {
    pub fn new(entry: u64, exit: u64, edge_type: EdgeType) -> Edge {
        Edge {entry: entry, exit: exit, edge_type}
    }

    pub fn contains(&self, addr: u64) -> bool {
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
                  end: bin.blocks[last_block].entry,
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

    pub fn subgraph(&self, root: u64) -> CFG {
        let order = dfs(self, root, &mut HashSet::new(), 0);
        let vertices: Vec<BasicBlock> = self.vertices.iter()
                                            .filter(|b| order.order
                                                             .contains_key(&b.entry))
                                            .cloned()
                                            .collect();
        let edges = self.edges.iter()
                              .filter(|e| order.order.contains_key(&e.entry) ||
                                          order.order.contains_key(&e.exit))
                              .cloned()
                              .collect();

        CFG {start: root, end: 0, edges: edges, vertices: vertices}
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
                    Some(addr) => edges.insert(Edge::new(block.entry, addr,
                                                         EdgeType::Directed)),
                    None => true,
                };

                /* If this instruction is not an unconditional control flow changing
                 * instruction (i.e. jmp, ret, etc.), then and edge from this block to
                 * the next sequential block should be added, if that block exists.
                 */
                if !last_insn.is_unconditional_cflow_ins() {
                    if CFG::block_exists(blocks, next_insn) {
                        edges.insert(Edge::new(block.entry, next_insn,
                                               EdgeType::Directed));
                    }
                }

            }
            /* If the last instruction isn't a control flow changing one, add an edge
             * to the next sequential block.
             */
            else {
                edges.insert(Edge::new(block.entry, next_insn, EdgeType::Directed));
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
                                edges.remove(&Edge::new(block.entry, addr,
                                                        EdgeType::Directed));
                                edges.insert(Edge::new(block.entry, next_insn,
                                                       EdgeType::Directed));
                            }
                        }

                    },
                    // If 'target' cannot be resolved, add a pseudo fall through edge.
                    None => if CFG::block_exists(blocks, next_insn) {
                        edges.insert(Edge::new(block.entry, next_insn,
                                               EdgeType::Directed));
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

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DominatorVertex<V: Vertex> {
    pub level: u64,
    pub vertex: V
}

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

impl fmt::Display for DominatorVertex<BasicBlock> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Vertex 0x{:x} @ level {}>", self.vertex.entry, self.level)
    }
}

#[derive(Clone)]
pub struct DominatorTree {
    pub root: u64,
    pub max_level: u64,
    pub vertices: Vec<DominatorVertex<BasicBlock>>,
    pub edges: HashSet<Edge>,
    pub cfg: CFG,
    pub dominators: HashMap<u64, HashSet<u64>>
}

impl DominatorTree {
    /* Requires 'cfg' to be fully connected. */
    pub fn new(cfg: &CFG, start: u64) -> DominatorTree {
        let block_entries: Vec<u64> = cfg.vertices
                                         .iter()
                                         .map(|b| b.entry)
                                         .collect();

        // Initialize Dom[s] = {s} and Dom[v] = V for v in V - {s}.
        let mut dominators: HashMap<u64, HashSet<u64>> = HashMap::new();
        let mut start_dom: HashSet<u64> = HashSet::new();
        start_dom.insert(start);
        dominators.insert(start, start_dom);
        for vertex in &cfg.vertices {
            if vertex.entry != start {
                dominators.insert(vertex.entry,
                                  HashSet::from_iter(block_entries.iter().cloned()));
            }
        }

        /* Iteratively build Dominator tree.
         */
        let mut updated_dominators = true;
        while updated_dominators {
            updated_dominators = false;

            for vertex in &block_entries {
                let mut dom_set: HashSet<u64> = HashSet::new();
                dom_set.insert(*vertex);

                let mut intersect: HashSet<u64> = HashSet::new();
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
                if dom_set != dominators[&vertex] {
                    updated_dominators = true;
                    match dominators.get_mut(vertex) {
                        Some(set) => *set = dom_set,
                        _ => panic!("Did not find block entry {}.", *vertex),
                    };
                }
            }
        }

        println!("*** DominatorTree Debugging Output ***");
        println!("Dominators:");
        for (addr, doms) in &dominators {
            print!("0x{:x} => {}", addr, "{");
            for d in doms {
                print!("0x{:x}, ", d);
            }
            println!("{}", "}");
        }
        println!("");

        /*
        for vertex in &block_entries {
            let mut doms = dominators[vertex].clone();
            if !doms.remove(vertex) {
                panic!("Vertex 0x{:x} not its own dominator", vertex);
            }
            print!("sdoms(0x{:x}): ", vertex);
            for d in doms {
                print!("0x{:x}, ", d);
            }
            println!("");
        }
        */

        println!("\nImmediate dominators:");
        // Add each (idom(x), x) edge.
        let mut edges: HashSet<Edge> = HashSet::new();
        for addr in block_entries {
            if addr != start {
                edges.insert(Edge::new(DominatorTree::idom(addr, &dominators), addr,
                                       EdgeType::DEdge));
                println!("idom(0x{:x}) = 0x{:x}", addr,
                         DominatorTree::idom(addr, &dominators));
            }
        }
        println!("\nCreated {} edges", edges.len());
        for edge in &edges {
            print!("{}, ", edge);
        }
        println!("\n*** End of Debugging ***");

        // Create set of DominatorVertex to preserve level information.
        let mut dom_vertices: Vec<DominatorVertex<BasicBlock>> = Vec::new();
        let mut max_level: u64 = 0;

        let mut queue: VecDeque<(u64, u64)> = VecDeque::new();
        queue.push_back((start, 0));

        let mut seen: HashSet<u64> = HashSet::new();
        seen.insert(start);

        while !queue.is_empty() {
            let (vertex, level) = match queue.pop_front() {
                Some((vertex, level)) => (vertex, level),
                None => panic!("Pop failed from nonempty queue")
            };

            if level > max_level {
                max_level = level;
            }

            // Add a queue item to the DominatorVertex set.
            match cfg.vertices.iter().position(|b| b.entry == vertex) {
                Some(i) => dom_vertices.push(DominatorVertex::new(cfg.vertices[i].clone(),
                                                                  level)),
                None => panic!("Node 0x{:x} not in set of basic blocks!", vertex),
            };
            /* Iterate through all D edges that originate from this vertex and add
             * them to the queue.
             */
            for edge in edges.iter()
                             .filter(|&e| e.edge_type == EdgeType::DEdge &&
                                          e.entry == vertex)
                             .cloned()
                             .collect::<Vec<_>>() {
                //if !seen.contains(&edge.entry) {
                queue.push_back((edge.exit, level + 1));
                    //seen.insert(edge.entry);
                //}
            }
        }

        assert_eq!(cfg.vertices.len(), dom_vertices.len());

        DominatorTree {root: start, max_level: max_level, vertices: dom_vertices,
                       edges: edges, cfg: cfg.clone(), dominators: dominators}
    }

    fn idom(vertex: u64, dominators: &HashMap<u64, HashSet<u64>>) -> u64 {
        let sdoms: HashSet<u64> = dominators[&vertex].iter()
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
    pub fn is_idom(&self, x: u64, y: u64) -> bool {
        self.edges.contains(&Edge::new(x, y, EdgeType::DEdge))
    }

    pub fn dominates(&self, x: u64, y: u64) -> bool {
        print!("Is 0x{:x} a dominator of 0x{:x}? Dominators for 0x{:x}: ", x, y, y);
        for dom in &self.dominators[&y] {
            print!("0x{:x}, ", dom);
        }
        println!("");
        self.dominators[&y].contains(&x)
    }

    pub fn from_binary(bin: &Binary, start: u64) -> Option<DominatorTree> {
        match bin.cfg() {
            Some(cfg) => Some(DominatorTree::new(&cfg, start)),
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
        let mut vertices: Vec<BasicBlock> = Vec::new();
        for vertex in &self.vertices {
            vertices.push(vertex.vertex.clone());
        }
        vertices
    }

    fn add_vertex(&mut self, vertex: BasicBlock) -> bool {
        false
    }

    fn root(&self) -> u64 {
        self.root
    }
}

pub struct DJGraph {
    pub start: u64,
    pub max_level: u64,
    pub vertices: Vec<DominatorVertex<BasicBlock>>,
    pub edges: HashSet<Edge>,
}

impl DJGraph {
    pub fn new(cfg: &CFG, start: u64) -> DJGraph {
        let dom_tree: DominatorTree = DominatorTree::new(&cfg, start);
        let mut edges = dom_tree.edges.clone();

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
    pub fn detect_loops(&mut self) -> Vec<Loop<DominatorVertex<BasicBlock>>> {
        let mut loops: Vec<Loop<DominatorVertex<BasicBlock>>> = Vec::new();

        // Need to identify sp-back edges from a spanning tree created via DFS.
        let ordering = dfs(self, self.start, &mut HashSet::new(), 0);
        let st = SpanningTree::new(ordering, &self.edges);
        let sp_back_edges: HashSet<Edge> = st.edges
                                             .iter()
                                             .filter(|v| v.edge_type == EdgeType::SPBack)
                                             .cloned()
                                             .collect();

        // Backwards traversal from lowest level to highest level in graph.
        for level in (0..self.max_level + 1).rev() {
            let mut irreducible_loop = false;

            // Get all vertices on current level
            for vertex in self.vertices.iter()
                                       .filter(|v| v.level == level)
                                       .collect::<Vec<_>>() {
                // Get call incoming edges (m_i, vertex).
                for edge in self.edges.iter()
                                      .filter(|e| e.exit == vertex.vertex.entry)
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
                        },
                        _ => println!("Edge {} is not a J edge", edge)
                    };
                }
                if irreducible_loop {
                    println!("SCC not implemented yet!");
                }
            }
        }

        loops
    }

    pub fn collapse_vertices(&mut self, vertices: &[u64], to_vertex: u64) {
        let edges = self.edges.iter()
                              .filter(|e| vertices.contains(&e.entry) ||
                                          vertices.contains(&e.exit))
                              .collect::<HashSet<_>>();
        let mut new_edges: HashSet<Edge> = HashSet::new();

        for edge in edges {
            /* Edges that originate from inside this set of vertices, but exit
             * elsewhere will be converted to an edge from the collapsed vertex to
             * exiting vertices.
             */
            if vertices.contains(&edge.entry) && !vertices.contains(&edge.exit) {
                new_edges.insert(Edge::new(to_vertex, edge.exit, edge.edge_type.clone()));
            }
            /* Edges originating outside this set to a vertex within this set will now
             * end at the collapsed vertex.
             */
            else if !vertices.contains(&edge.entry) && vertices.contains(&edge.exit) {
                new_edges.insert(Edge::new(edge.entry, to_vertex, edge.edge_type.clone()));
            }
            // Note: Edges from and to vertices within the set are dropped.
        }
        println!("Old edges: [{}]", self.edges.iter()
                                              .map(|e| format!("{}", e))
                                              .collect::<Vec<String>>()
                                              .join(", "));
        println!("New edges: [{}]", new_edges.iter()
                                             .map(|e| format!("{}", e))
                                             .collect::<Vec<String>>()
                                             .join(", "));
    }

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
}

impl Graph<BasicBlock> for DJGraph {
    fn get_edges(&self) -> &HashSet<Edge> {
        &self.edges
    }

    fn add_edge(&mut self, edge: Edge) -> bool {
        self.edges.insert(edge)
    }

    fn get_vertices(&self) -> Vec<BasicBlock> {
        let mut vertices: Vec<BasicBlock> = Vec::new();
        for vertex in &self.vertices {
            vertices.push(vertex.vertex.clone());
        }
        vertices
    }

    fn add_vertex(&mut self, vertex: BasicBlock) -> bool {
        false
    }

    fn root(&self) -> u64 {
        self.start
    }
}

pub struct SpanningTree {
    vertices: Vec<u64>,
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

    pub fn path_to(&self, origin: u64, destination: u64) -> Option<Vec<u64>> {
        SpanningTree::path(origin,
                           destination,
                           &self.edges.iter()
                                      .filter(|e| e.edge_type == EdgeType::SPTree)
                                      .cloned()
                                      .collect::<HashSet<_>>())
    }

    fn path(origin: u64, destination: u64, tree_edges: &HashSet<Edge>)
            -> Option<Vec<u64>> {
        for edge in tree_edges.iter()
                              .filter(|e| e.entry == origin)
                              .collect::<HashSet<_>>() {
            if edge.exit == destination {
                return Some(vec![origin, destination]);
            }
            match SpanningTree::path(edge.exit, destination, tree_edges) {
                Some(mut v) => {
                    let mut ret: Vec<u64> = vec![origin];
                    ret.append(&mut v);
                    return Some(ret);
                }
                None => (),
            };
        }

        None
    }
}

pub struct Ordering {
    order: HashMap<u64, u64>,
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

pub fn dfs<G: Graph<BasicBlock>>(graph: &G, root: u64, seen: &mut HashSet<u64>,
                                 depth: u64) -> Ordering {
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
pub fn connected_components<G: Graph<BasicBlock>>(graph: &G) -> Vec<Ordering> {
    let mut components: Vec<Ordering> = Vec::new();
    let mut vertices: HashSet<BasicBlock> = HashSet::from_iter(graph.get_vertices()
                                                                    .iter()
                                                                    .cloned());

    while !vertices.is_empty() {
        for vertex in &vertices {
            /* If this vertex has no predecessors, treat it as a starting point and
             * get the subgraph.
             */
            if graph.get_predecessors(vertex.entry).is_empty() {
                components.push(dfs(graph, vertex.entry, &mut HashSet::new(), 0));
                break;
            }
        }

        if let Some(order) = components.last() {
            for addr in order {
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

// TODO: determine return type for the following function!
pub fn strongly_connected_components<G: Graph<BasicBlock>>(graph: G) {
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Loop<V: Vertex> {
    pub entry: u64,
    pub body: Vec<V>
}

use std::fmt;

#[derive(Clone, PartialEq)]
pub enum SymbolType {
    SymTypeUnk,
    SymTypeNone,
    SymTypeFunc,
    SymTypeSection,
    SymTypeFile,
    SymTypeObject
}

#[derive(Clone, PartialEq)]
pub enum SymbolBinding {
    SymBindLocal,
    SymBindGlobal,
    SymBindWeak,
    SymBindUnk,
}

#[derive(Clone, PartialEq)]
pub enum SymbolVisability {
    SymVisDefault,
    SymVisHidden,
}

#[derive(Clone, PartialEq)]
pub enum SymbolTable {
    SymTabStatic,
    SymTabDynamic,
}

#[derive(Clone, PartialEq)]
pub struct Symbol {
    pub sym_type: SymbolType,
    pub name: String,
    pub addr: u64,
    pub binding: SymbolBinding,
    //pub visability: SymbolVisability,
    pub table: SymbolTable,
}

impl Symbol {
    pub fn new<'c>(sym_type: SymbolType, name: String, addr: u64,
                   binding: SymbolBinding, table: SymbolTable) -> Symbol {
        Symbol {
            sym_type: sym_type,
            name: name,
            addr: addr,
            binding: binding,
            table: table,
        }
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:016x} {} {} {}", self.addr, self.sym_type,
               self.binding, self.name)
    }
}

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let st_str = match self {
            SymbolType::SymTypeNone => "None",
            SymbolType::SymTypeFunc => "Func",
            SymbolType::SymTypeSection => "Sec",
            SymbolType::SymTypeFile => "File",
            SymbolType::SymTypeObject => "Obj",
            SymbolType::SymTypeUnk => "Unk",
        };
        write!(f, "{:4}", st_str)
    }
}

impl fmt::Display for SymbolBinding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sb_str = match self {
            SymbolBinding::SymBindLocal => "Local",
            SymbolBinding::SymBindGlobal => "Global",
            SymbolBinding::SymBindWeak => "Weak",
            SymbolBinding::SymBindUnk => "Unk",
        };
        write!(f, "{:6}", sb_str)
    }
}

impl fmt::Display for SymbolTable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let st_str = match self {
            SymbolTable::SymTabStatic => "Static",
            SymbolTable::SymTabDynamic => "Dynamic",
        };
        write!(f, "{}", st_str)
    }
}


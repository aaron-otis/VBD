use std::fmt;

pub enum SymbolType {
    SymTypeUnk,
    SymTypeNone,
    SymTypeFunc,
    SymTypeSection,
    SymTypeFile,
    SymTypeObject
}

pub enum SymbolBinding {
    SymBindLocal,
    SymBindGlobal,
    SymBindWeak,
    SymBindUnk,
}

pub enum SymbolVisability {
    SymVisDefault,
    SymVisHidden,
}

pub enum SymbolTable {
    SymTabStatic,
    SymTabDynamic,
}

#[derive(Clone)]
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

impl Clone for SymbolType {
    fn clone (&self) -> SymbolType {
        match self {
            SymbolType::SymTypeUnk => SymbolType::SymTypeUnk,
            SymbolType::SymTypeNone => SymbolType::SymTypeNone,
            SymbolType::SymTypeFunc => SymbolType::SymTypeFunc,
            SymbolType::SymTypeSection => SymbolType::SymTypeSection,
            SymbolType::SymTypeFile => SymbolType::SymTypeFile,
            SymbolType::SymTypeObject => SymbolType::SymTypeObject,
        }
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

impl Clone for SymbolBinding {
    fn clone (&self) -> SymbolBinding {
        match self {
            SymbolBinding::SymBindLocal => SymbolBinding::SymBindLocal,
            SymbolBinding::SymBindGlobal => SymbolBinding::SymBindGlobal,
            SymbolBinding::SymBindWeak => SymbolBinding::SymBindWeak,
            SymbolBinding::SymBindUnk => SymbolBinding::SymBindUnk,
        }
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

impl Clone for SymbolTable {
    fn clone (&self) -> SymbolTable {
        match self {
            SymbolTable::SymTabStatic => SymbolTable::SymTabStatic,
            SymbolTable::SymTabDynamic => SymbolTable::SymTabDynamic,
        }
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


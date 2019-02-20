use bfd::load_binary;

pub enum SectionType {
    SecTypeNone,
    SecTypeCode,
    SecTypeData,
}

pub enum BinaryType {
    BinTypeAuto,
    BinTypeELF,
    BinTypePE,
}

pub enum BinaryArch {
    ArchNone,
    ArchX86,
    ArchArm,
    ArchX86_64,
    ArchArm64,
    ArchRISCV,
}

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

#[derive(Clone)]
pub struct Section {
    //pub binary: &Binary,
    pub name: String,
    pub sec_type: SectionType,
    pub vma: u64,
    pub size: u64,
    pub bytes: Vec<u8>,
}

impl Binary {
    pub fn new<'b>(fname: String) -> Result<Binary, LoadError> {
        match load_binary(fname.clone()) {
            Ok(b) => return Ok(b),
            Err(e) => return Err(e),
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

impl Section {
    pub fn new(name: String, sec_type: SectionType, vma: u64, size: u64,
               bytes: Vec<u8>) -> Result<Section, LoadError> {
        Ok(Section {
            /*
            binary: match Binary::new("".to_string()){
                Ok(b) => b,
                Err(e) => return Err(e),
            },
            */
            name: name,
            sec_type: sec_type,
            vma: vma,
            size: size,
            bytes: bytes,
        })
    }

    pub fn contains(&self, addr: u64) -> bool {
        (addr >= self.vma) && (addr - self.vma <= self.size)
    }
}

impl Clone for BinaryType {
    fn clone (&self) -> BinaryType {
        match self {
            BinaryType::BinTypeAuto => BinaryType::BinTypeAuto,
            BinaryType::BinTypeELF => BinaryType::BinTypeELF,
            BinaryType::BinTypePE => BinaryType::BinTypePE,
        }
    }
}

impl Clone for BinaryArch {
    fn clone (&self) -> BinaryArch {
        match self {
            BinaryArch::ArchNone => BinaryArch::ArchNone,
            BinaryArch::ArchX86 => BinaryArch::ArchX86,
            BinaryArch::ArchArm => BinaryArch::ArchArm,
            BinaryArch::ArchX86_64 => BinaryArch::ArchX86_64,
            BinaryArch::ArchArm64 => BinaryArch::ArchArm64,
            BinaryArch::ArchRISCV => BinaryArch::ArchRISCV,
        }
    }
}

impl Clone for SectionType {
    fn clone (&self) -> SectionType {
        match self {
            SectionType::SecTypeNone => SectionType::SecTypeNone,
            SectionType::SecTypeCode => SectionType::SecTypeCode,
            SectionType::SecTypeData => SectionType::SecTypeData,
        }
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

impl Clone for SymbolTable {
    fn clone (&self) -> SymbolTable {
        match self {
            SymbolTable::SymTabStatic => SymbolTable::SymTabStatic,
            SymbolTable::SymTabDynamic => SymbolTable::SymTabDynamic,
        }
    }
}


pub fn print_binary(bin: &Binary) {
    println!("File:\t{}\nType:\t{}\nArch:\t{}\nEntry:\t0x{:016x}\n",
             bin.filename, bin.type_str, bin.arch_str, bin.entry);
}

pub fn print_sections(sections: &Vec<Section>) {
    println!("\nSections:");
    println!("{:24} {:4} {:18} {}", "Name", "Type", "Address", "Size");
    for sec in sections {
        let sec_type = match sec.sec_type {
            SectionType::SecTypeCode => "Code",
            SectionType::SecTypeData => "Data",
            _ => "None",
        };
        println!("{:24} {:4} 0x{:016x} {}", sec.name, sec_type, sec.vma, sec.size);
    }
    print!("\n");
}

pub fn print_symbols(symbols: &Vec<Symbol>) {
    fn print_syms(symbols: &Vec<Symbol>) {
        println!("{:<6} {:<18} {:<4} {:<6} {:<}", "Num", "Value", "Type",
                 "Bind", "Name");
        let mut i = 0;
        for sym in symbols {
            let sym_type = match sym.sym_type {
                SymbolType::SymTypeNone => "None",
                SymbolType::SymTypeFunc => "Func",
                SymbolType::SymTypeSection => "Sec",
                SymbolType::SymTypeFile => "File",
                SymbolType::SymTypeObject => "Obj",
                SymbolType::SymTypeUnk => "Unk",
            };

            let binding = match sym.binding {
                SymbolBinding::SymBindLocal => "Local",
                SymbolBinding::SymBindGlobal => "Global",
                SymbolBinding::SymBindWeak => "Weak",
                SymbolBinding::SymBindUnk => "Unk",
            };

            println!("{:5}: 0x{:016x} {:4} {:6} {}", i, sym.addr, sym_type, binding,
                     sym.name);
            i += 1;
        }
    }

    // Sort static and dynamic symbols into their own vectors. Note that there
    // were issues encountered using collec() and so this work around was used.
    let mut dsymtab: Vec<Symbol> = Vec::new();
        /*
        symbols.into_iter()
                         .filter(|sym| match sym.table {
                             SymbolTable::SymTabDynamic => true,
                             _ => false,
                         }).collect();
         */
    let mut ssymtab: Vec<Symbol> = Vec::new();
    for sym in symbols {
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

pub fn print_section_contents(section: &Section) {
    println!("{}", section.name);
    print_bytes(&section.bytes);
}

pub fn print_bytes(bytes: &Vec<u8>) {
    let width: usize = 16;
    let mut lineno: usize = 0;

    for chunk in bytes.chunks(width) {
        for i in 0..chunk.len() {
            match i % 2 {
                0 => print!("{:02x}", chunk[i]),
                _ => print!("{:02x} ", chunk[i]),
            };
        }

        if chunk.len() < width {
            let difference = width - chunk.len();
            print!("{:1$}", "", 2 * difference + difference / 2 + 1);
        }

        print!("\t");
        for byte in chunk {
            match byte.is_ascii_alphanumeric() {
                true => print!("{}", *byte as char),
                false => print!("."),
            };
        }
        print!("\n");
        lineno += width;
    }
    print!("\n");
}

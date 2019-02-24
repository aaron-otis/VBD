use std::fmt;
use super::binary::LoadError;

pub enum SectionType {
    SecTypeNone,
    SecTypeCode,
    SecTypeData,
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

impl Section {
    pub fn new(name: String, sec_type: SectionType, vma: u64, size: u64,
               bytes: Vec<u8>) -> Result<Section, LoadError> {
        Ok(Section {
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

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:24} {} 0x{:016x} {}", self.name, self.sec_type, self.vma,
               self.size)
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

impl fmt::Display for SectionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sec_type = match self {
            SectionType::SecTypeCode => "Code",
            SectionType::SecTypeData => "Data",
            _ => "None",
        };
        write!(f, "{:4}", sec_type)
    }
}

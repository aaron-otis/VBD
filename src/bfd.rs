#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Include FFI function generated by bindgen.
include!(concat!(env!("OUT_DIR"), "/bgen_bfd.rs"));

extern crate libc;

use self::libc::{c_void, c_long};
use std::ffi::{CString, CStr};
use std::fs::File;
use std::io::Read;
use std::ptr;
use binary::binary::{Binary, BinaryArch, BinaryType, LoadError};
use binary::symbol::{Symbol, SymbolType, SymbolBinding, SymbolTable};
use binary::section::{Section, SectionType};

pub fn load_binary(fname: String) -> Result<Binary, LoadError> {

    unsafe {
        // Open binary file.
        let bfd_h = match open_binary(fname.clone()) {
            Ok(bfd_h) => bfd_h,
            Err(e) => return Err(e),
        };

        // Determine the type and type string.
        let type_str = CStr::from_ptr((*(*bfd_h).xvec).name).to_string_lossy();
        let flavor = match (*(*bfd_h).xvec).flavour {
            bfd_flavour_bfd_target_elf_flavour => BinaryType::BinTypeELF,
            bfd_flavour_bfd_target_coff_flavour => BinaryType::BinTypePE,
            _ => return Err(LoadError::UnsupportedType),
        };

        // Get architecture info.
        let bfd_info = bfd_get_arch_info(bfd_h);
        let arch_str = CStr::from_ptr((*bfd_info).printable_name).to_string_lossy();
        let (arch, bits) = match (*bfd_info).mach {
            4 => (BinaryArch::ArchX86, 32),
            8 => (BinaryArch::ArchX86_64, 64),
            _ => return Err(LoadError::UnsupportedArch),
        };

        // Best effort to load symbols (may not be present).
        let symbols = match load_symbols(bfd_h) {
            Ok(vec) => vec,
            Err(e) => return Err(e),
        };

        // Load sections.
        let sections = match load_sections(bfd_h) {
            Ok(vec) => vec,
            Err(e) => return Err(e),
        };

        // Copy bytes.
        let mut bytes: Vec<u8> = Vec::new();
        let mut file = match File::open(fname.clone()) {
            Ok(f) => f,
            Err(e) => panic!("Failed to open {}: {}", fname.clone(), e)
        };
        file.read_to_end(&mut bytes);

        Ok(Binary {
            filename: fname,
            bin_type: flavor,
            type_str: type_str.into_owned(),
            arch: arch,
            arch_str: arch_str.into_owned(),
            bits: bits,
            entry: (*bfd_h).start_address,
            sections: sections,
            symbols: symbols,
            functions: Vec::new(),
            blocks: Vec::new(),
            bytes: bytes,
            max_vertices: 0 // Placeholder.
        })
    }
}

fn open_binary(fname: String) -> Result<*mut bfd, LoadError> {
    let new_name = CString::new(fname.clone())
                            .expect("Failed to create CString in openbfd");
    unsafe {
        let bfd_h: *mut bfd; 
        bfd_init();
        bfd_h = bfd_openr(new_name.as_ptr(), ptr::null());

        // Panic if bfd_openr fails.
        if bfd_h.is_null() {
            return Err(LoadError::OpenFileError)
        }

        // Verify that bfd_h is the correct format.
        if bfd_check_format(bfd_h, bfd_format_bfd_object) == 0 {
            return Err(LoadError::InvalidFormat)
        }

        // Reset bfd_error just in case the library is being sloppy.
        bfd_set_error(bfd_error_bfd_error_no_error);

        // Panic if invalid flavor is detected.
        match (*(*bfd_h).xvec).flavour {
            bfd_flavour_bfd_target_unknown_flavour  =>
                return Err(LoadError::UnrecognizedFormat),
            _ => (),
        }

        Ok(bfd_h)
    }
}

fn load_symbols(bfd_h: *mut bfd) -> Result<Vec<Symbol>, LoadError> {
    unsafe {
        let mut symbols: Vec<Symbol> = Vec::new();

        for table in [SymbolTable::SymTabStatic, SymbolTable::SymTabDynamic].iter() {

            // Get correct upper bound for the table in question.
            let upper_bound: c_long = match table {
                SymbolTable::SymTabStatic =>
                    match (*(*bfd_h).xvec)._bfd_get_symtab_upper_bound {
                        Some(f) => f(bfd_h),
                        None => 0,
                    }
                SymbolTable::SymTabDynamic =>
                    match (*(*bfd_h).xvec)._bfd_get_dynamic_symtab_upper_bound {
                        Some(f) => f(bfd_h),
                        None => 0,
                    }
            };

            // Error check upper bound.
            if upper_bound <= 0 {
                continue;
            }

            // Allocate space for an array of pointers.
            let mut symtab: Vec<*mut asymbol> =
                vec![ptr::null_mut() as *mut asymbol; upper_bound as usize];

            let nsyms: c_long = match table {
                SymbolTable::SymTabStatic => {
                            match (*(*bfd_h).xvec)._bfd_canonicalize_symtab {
                                Some(f) => f(bfd_h, symtab.as_mut_ptr()),
                                None => 0,
                            }
                },
                SymbolTable::SymTabDynamic => {
                            match (*(*bfd_h).xvec)._bfd_canonicalize_dynamic_symtab {
                                Some(f) => f(bfd_h, symtab.as_mut_ptr()),
                                None => 0,
                            }
                },
            };

            // Resize symtab.
            symtab.truncate(nsyms as usize);

            for sym in symtab {
                let name = CStr::from_ptr((*sym).name).to_string_lossy()
                                                      .to_string();
                let sym_type = match (*sym).flags {
                    flag if (flag == 0) => SymbolType::SymTypeNone,
                    flag if (flag & 8 == 8) => SymbolType::SymTypeFunc,
                    flag if (flag & (1 << 8) == 1 << 8) => SymbolType::SymTypeSection,
                    flag if (flag & (1 << 14) == 1 << 14) => SymbolType::SymTypeFile,
                    flag if (flag & (1 << 16) == 1 << 16) => SymbolType::SymTypeObject,
                    _ => SymbolType::SymTypeNone,
                };

                let binding = match (*sym).flags {
                    flag if (flag & 1 == 1) => SymbolBinding::SymBindLocal,
                    flag if (flag & 2 == 2) => SymbolBinding::SymBindGlobal,
                    flag if (flag & (1 << 7) == 1 << 7) => SymbolBinding::SymBindWeak,
                    _ => SymbolBinding::SymBindUnk,
                };

                symbols.push(Symbol {
                                sym_type: sym_type,
                                name: name,
                                /* Symbol values have multiple meanings based on their
                                 * contexts. In relocatable files, the value is an
                                 * offset into the section it is contained in, unless
                                 * the section index is SHN_COMMON. In this case, the
                                 * value field holds alignment constraints. In executable
                                 * and shared objects, the value is a virtual address.
                                 */
                                addr: match (*sym).flags {
                                    // This is a virtual address.
                                    0x8002 => (*sym).value as u64,
                                    // This is an offset.
                                    _ => (*(*sym).section).vma as u64 +
                                        (*sym).value as u64,
                                },
                                binding: binding,
                                table: match table {
                                    SymbolTable::SymTabStatic => 
                                        SymbolTable::SymTabStatic,
                                    SymbolTable::SymTabDynamic => 
                                        SymbolTable::SymTabDynamic,
                                },
                             });
            }
        }

        Ok(symbols)
    }
}

fn load_sections(bfd_h: *mut bfd) -> Result<Vec<Section>, LoadError> {

    let mut sections: Vec<Section> = Vec::new();

    unsafe {
        let mut bfd_sec = (*bfd_h).sections;

        while !bfd_sec.is_null() {
            // Determine the type.
            let sec_type = match (*bfd_sec).flags {
                c if (c & SEC_CODE == SEC_CODE) => SectionType::SecTypeCode,
                d if (d & SEC_DATA == SEC_DATA) => SectionType::SecTypeData,
                _ => SectionType::SecTypeNone,
            };

            // Determine the section name. Section may be unnamed.
            let sec_name = match (*bfd_sec).name {
                ptr if (ptr.is_null()) => "unamed".to_string(),
                _ => CStr::from_ptr((*bfd_sec).name).to_string_lossy().to_string(),
            };

            // Create a vector for the section contents and fill it.
            let mut bytes: Vec<u8> = vec![0 as u8; (*bfd_sec).size as usize];
            match bfd_get_section_contents(bfd_h,
                                           bfd_sec, bytes.as_mut_ptr() as *mut c_void,
                                           0,
                                           (*bfd_sec).size) {
                0 => {
                    bfd_sec = (*bfd_sec).next;
                    continue;
                },
                _ => (),
            };
            sections.push(Section{
                            name: sec_name,
                            sec_type: sec_type,
                            vma: (*bfd_sec).vma as u64,
                            size: (*bfd_sec).size as u64,
                            bytes: bytes,
                          });
            bfd_sec = (*bfd_sec).next;
        }
    }

    Ok(sections)
}

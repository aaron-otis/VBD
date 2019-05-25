# Very Bad Disassembler

This is a recursive disassembler that uses [Capstone](https://github.com/aquynh/capstone) to collect statistical information on binaries such as:
* Instruction counts
* Loops

It currently does several things poorly, such as using the Capstone C library from the Rust FFI instead of the [bindings for Rust](https://crates.io/crates/capstone) as well as libbfd instead of a Rust binary loader library such as [goblin](https://crates.io/crates/goblin). This might be fixed in the future, but don't count on it.

Seriously, you should use a refined tool, not something I created to complete my Master's Thesis.

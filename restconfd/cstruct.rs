
#[repr(C)]
#[derive(Debug, Default)]
pub struct CStruct {
    char: u8,
    long: u64,
    int: u32,
    short: u16,
}

use core::mem::offset_of;

pub fn test_cstruct() {
    let c = CStruct{char: 1, short: 2, int: 3, long: 4};
    // let c = CStruct{..Default::default()};
    // let cp = c.as_ptr();
    let coff = offset_of!(CStruct, int);

    println!("{:?} offset of int is {}", c, coff)
}

// Cast anything to a u8 slice for hexdump
// unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
//     ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
// }

#[repr(C)]
#[derive(Debug, Default)]
pub struct CStruct {
    char: u8,
    short: u16,
    int: u32,
    long: u64,
}

use core::mem::offset_of;
use tracing::debug;

pub fn test_cstruct() {
    let c = CStruct {
        char: 1,
        short: 2,
        int: 3,
        long: 4,
    };
    let data: [u8; 16] = [
        0x0B, 0x0, 0x02, 0x01, 0x3, 0x0, 0x0, 0x1, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x01,
    ];
    // let c = CStruct{..Default::default()};
    // let cp = c.as_ptr();
    let coff = offset_of!(CStruct, int);

    debug!("{:?} offset of int is {}", c, coff);

    // let ary = unsafe { any_as_u8_slice(&c) };
    // hexdump::hexdump(ary);
    // hexdump::hexdump(&data);

    let things_p: *const CStruct = data.as_ptr() as *const CStruct;
    unsafe {
        let things: &CStruct = &*things_p;
        debug!("from data to struct {:0x?}", things);
    }
}

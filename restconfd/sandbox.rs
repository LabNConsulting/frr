// fn largest<T>(list: &[T]) -> &T
// where
//     T: std::cmp::PartialOrd,
// {
//     let mut largest = &list[0];
//     for item in list {
//         if item > largest {
//             largest = item;
//         }
//     }
//     largest
// }

// fn main() {
//     let nlist = vec![3, 6, 12, 4];
//     let clist = vec!['y', 'z', 'd'];
//     println!("largest number: {}", largest(&nlist));
//     println!("largest char: {}", largest(&clist));
// }
use std::f64::consts::PI;
use std::ops::Deref;

pub struct Circle<T> {
    r: T,
}

pub struct Rect<T> {
    x: T,
    y: T,
}

pub trait Bounded {
    fn area(&self) -> f64;
    fn boundary(self: &Self) -> f64;
}

impl Bounded for Circle<u64> {
    fn area(&self) -> f64 {
        PI * (self.r * self.r) as f64
    }
    fn boundary(&self) -> f64 {
        2.0 * PI * self.r as f64
    }
}
impl Bounded for Circle<f64> {
    fn area(&self) -> f64 {
        PI * self.r * self.r
    }
    fn boundary(&self) -> f64 {
        2.0 * PI * self.r
    }
}

impl Bounded for Rect<u64> {
    fn area(&self) -> f64 {
        (self.x * self.y) as f64
    }
    fn boundary(&self) -> f64 {
        2.0 * (self.x + self.y) as f64
    }
}

impl Bounded for Rect<f64> {
    fn area(&self) -> f64 {
        self.x * self.y
    }
    fn boundary(&self) -> f64 {
        2.0 * (self.x + self.y)
    }
}

fn print_shape_info(shape: &impl Bounded) {
    println!(
        "Boundary of shape is {} long and area is {}",
        shape.boundary(),
        shape.area()
    )
}

const fn u32_to_array(ival: u32) -> [u8; 4] {
    [
        (ival & 0xff) as u8,
        ((ival >> 8) & 0xff) as u8,
        ((ival >> 16) & 0xff) as u8,
        ((ival >> 24) & 0xff) as u8,
    ]
}

// fn u32_to_array(ival: u32) -> [u8; std::mem::size_of::<u32>()]
// {
//     const NBYTES: usize = std::mem::size_of::<u32>();
//     let mut ary = [0u8; NBYTES];
//     let mut mival = ival;
//     for i in 0..NBYTES {
//         ary[i] =  (mival & 0xff) as u8;
//         mival = mival >> 8;
//     }
//     ary
// }

// fn int2array<T>(ival: T) -> [u8; std::mem::size_of::<T>()]
//     where T: std::ops::BitAnd + std::ops::Shr<Output = T> + Sized,
// {
//     const NBYTES: usize = std::mem::size_of::<T>();
//     let mut ary = [0u8; NBYTES];
//     let mut mival = ival;
//     for i in 0..NBYTES {
//         let bval = (mival & 0xff) as u8;
//         ary[i] = bval;
//         mival = mival >> 8;
//     }
//     ary
// }

// Looking at uninitialized arrays -- not allowed
// fn zero(ary: &mut [u8]) {
//     for item in ary {
//         *item = 0
//     }
// }
// fn test_const<const N: usize>() -> [u8; N] {
//     let ary: [u8; N] = core::array::from_fn(|_| 0);
//     let mut ary2: [u8; N];
//     zero(&mut ary2);
//     println!("test_const<N> N = {}", N);
//     ary
// }

// //
// // Recieve a constant sized array from the client.
// //
// // The size will normally be inferred by the value being assigned to.
// fn recv_wait_gen<const N: usize>(client: &mut MgmtdClient) -> Result<[u8; N]> {
//     let mut ary: [u8; N];
//     client.stream.read_exact(&mut ary)?;
//     Ok(ary)
// }
// let ary: [u8; 4] = recv_wait_gen(client)?;

fn main() {
    let c = Circle { r: 2.0 };
    let ci = Circle { r: 2 };
    let r = Rect { x: 4.0, y: 5.0 };
    let ri = Rect { x: 4, y: 5 };

    if false {
        print_shape_info(&c);
        print_shape_info(&ci);
        print_shape_info(&r);
        print_shape_info(&ri);

        let sz: u32 = 1025;
        let szp: *const u32 = &sz;
        let memp: *const u8 = szp as *const u8;
        let _memr: &u8 = unsafe { &*memp };
        let aryp: *const [u8; 4] = memp as *const [u8; 4];
        let aryr: &[u8] = unsafe { &*aryp };
        println!("szp: {:x?}", szp);
        println!("aryp: {:x?}", aryp);
        println!("*aryp: {:x?}", unsafe { *aryp });
        println!("aryr: {:x?}", aryr);
        for u in [513, 255 << 8, 0x01020304] {
            println!("u32_to_array({:x?}): {:x?}", u, u32_to_array(u));
        }
        println!("{:x?}", '#' as u32);

        for i in 0..2 {
            println!("{i:?}");
        }

        // let _ary: [u8; 8] = test_const();

        // const EMPTY: Option<u8> = None;
        // let foo = [EMPTY; 100];
        // println!("empty foo {:?}", foo);
        let bar = [const { None }; 100];
        println!("empty bar {:?}", bar);
        let _baz: u8 = bar[1].unwrap_or_else(|| 0);
        // bar[1] = Some(0xFF);
        // println!("empty bar {:?}", bar);
    } else {
        let i = Box::new(5);
        println!("i: {:?}", i);
        print(&i);
        println!("i: {:?}", i);


        let x = Baz { b: Bar { f: Foo { n: 5 }}};
        // println!("x: {:?}", &x);
        printfoo(&x.b.f);
        // dereference conversion
        printfoo(&x);
    }

    // let b = vec![0, 2, 4, 6, 8];


}

fn printfoo(x: &Foo)
{
    println!("n: {:?}", x.n);
}


fn print<T: core::fmt::Debug>(b: &Box<T>)
{
    println!("boxed: {:?}", b);
}

struct Foo {
    n: i32,
}

impl Deref for Foo {
    type Target = i32;

    fn deref(&self) -> &Self::Target {
        &self.n
    }
}

struct Bar {
    f: Foo
}

impl Deref for Bar {
    type Target = Foo;

    fn deref(&self) -> &Foo {
        &self.f
    }
}

struct Baz {
    b: Bar
}

impl Deref for Baz {
    type Target = Bar;

    fn deref(&self) -> &Bar {
        &self.b
    }
}

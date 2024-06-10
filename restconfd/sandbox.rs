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

fn main() {
    let c = Circle { r: 2.0 };
    let ci = Circle { r: 2 };
    let r = Rect { x: 4.0, y: 5.0 };
    let ri = Rect { x: 4, y: 5 };

    print_shape_info(&c);
    print_shape_info(&ci);
    print_shape_info(&r);
    print_shape_info(&ri);
}

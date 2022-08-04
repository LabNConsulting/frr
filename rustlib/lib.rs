#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

#[no_mangle]
pub extern "C" fn example_function() {
    println!("hello, world");
}

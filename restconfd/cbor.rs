

fn encode(input: &[&str]) -> [u8; 128] {
    let mut buffer = [0u8; 128];

    minicbor::encode(&input, buffer.as_mut()).unwrap();
    buffer
}

fn decode(buffer: &[u8]) -> [&str; 2] {
    minicbor::decode(buffer.as_ref()).unwrap()
}

pub fn test_cbor() {
    let input = ["hello", "world"];
    let buffer = encode(&input);
    let output = decode(&buffer);

    assert_eq!(input, output);

    println!("output: [0]: {} [1]: {}", output[0], output[1]);
}

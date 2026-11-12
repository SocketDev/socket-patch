fn main() {
    let new = itoa::Buffer::new().format(1015u64).to_owned();
    let old = itoa04::Buffer::new().format(48u64).to_owned();
    println!("ITOA={new} ITOA04={old}");
}

mod sdes;

fn main() {
    let sdes: sdes::SDES = sdes::SDES::new(0b1100101101);
    let cipher: String = sdes.encrypt("hello world");
    let message: String = sdes.decrypt(&cipher);
    println!("hello world => {0}", cipher);
    println!("{0} => {1}", cipher, message);
}

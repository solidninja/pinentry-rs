#![deny(warnings)]
#[warn(unused_must_use)]
extern crate pinentry_rs;

use std::str;
use pinentry_rs::pinentry;

fn main() {
    let pin = pinentry()
        .window_title("Unlock disk".to_string())
        .description("A disk has no key.".to_string())
        .pin("Enter passphrase to unlock:".to_string())
        .expect("A password");

    println!("PIN: {}", pin);

    // now print the real pin (unsecure!)
    println!("UNSECURE REAL PIN: {}", str::from_utf8(pin.unsecure()).unwrap());
}
#![feature(nll)]

extern crate digest as digest_external;
extern crate generic_array;

mod digest;
mod reference;

pub use digest::sha3;
pub use reference::State;

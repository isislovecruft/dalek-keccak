#![feature(nll)]

extern crate digest;

mod reference;

pub mod digests;

pub mod keccak {
    pub use reference::State;
}

#[cfg(test)]
extern crate sha3;

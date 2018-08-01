#![feature(nll)]
#![feature(trace_macros)]

extern crate digest;

#[macro_use]
mod macros;
mod reference;

pub mod digests;

pub mod keccak {
    pub use reference::State;
}

#[cfg(test)]
extern crate sha3;

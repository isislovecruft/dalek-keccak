#![feature(test)]
#[macro_use]
extern crate digest;
extern crate sha3;
extern crate dalek_keccak;

//bench_digest!(sha3::Sha3_256);
bench_digest!(dalek_keccak::digests::Sha3_256);

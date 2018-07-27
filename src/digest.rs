// -*- mode: rust; coding: utf-8; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2018 Henry de Valence, isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

use core::vec::Vec;

use digest_external::BlockInput;
use digest_external::Input;
use digest_external::FixedOutput;

pub use digest_external::Digest;

use generic_array::typenum::{U28, U32, U48, U56, U64, U96, U128};

use super::State;

pub trait Padding {
    fn pad(length: usize) -> Vec<u8>;
}

pub struct PadOneZeroStarOne{ }

impl Padding for PadOneZeroStarOne<'p> {
    /// Pad the message `m` to a multiple of `x` bits.
    ///
    /// # Returns
    ///
    /// The padding bytes.
    ///
    /// # Note
    ///
    /// This function is modified from the specification to prepend the message
    /// here, rather than in the aborb function of the sponge.
    fn pad(x: usize, m: &[u8]) -> Vec<u8> {
        debug_assert!(x > 0); // x must be positive

        let l: usize = m.len();
        let j: usize = (l - 2) % (x / 8);
        let p: Vec<u8> = Vec::with_capacity(l+j);

        p.extend_from_slice(m);
        p.push(0x01);

        for _ in (1..j) {
            p.push(0x00);
        }
        p.push(0x01);
        p
    }
}

pub trait Sponge {
    type Pad: Padding;
    type Rate: ArrayLength<u8>;

    fn absorb(&mut self, input: &[u8]);
    fn squeeze(&mut self, length: usize) -> &[u8];
}

macro_rules! bits_to_bytes {
    // Sizes for blocks and outputs
    (224)  => {U28};
    (256)  => {U32};
    (384)  => {U48};
    (512)  => {U64};

    // Sizes for keccak rates and capacities
    (448)  => {U56};
    (768)  => {U96};
    (1024) => {U128};
}

macro_rules! impl_hash_function {
    ( $name:ident,
      $blocksize:expr,
      $capacity:expr,
      $rate:expr,
      $rounds:expr,
      $outputsize:expr
    ) => {
        impl Sponge for $name {
            type Pad = PadOneZeroStarOne;
            type Rate = bits_to_bytes!($rate);

            fn absorb(&mut self, input: &[u8]) {
                let p: Vec<u8> = Self::Pad::pad(input);
                let n: usize = p.len() - ($rate as usize);
                let c: usize = ($blocksize as usize) - ($rate as usize);
                
                for chunk in p.exact_chunks($rate) {
                    for i in 0..$rate {
                        self.0[i] ^= chunk[i];
                    }
                }
                let z: Vec<u8> = p.truncate($rate);

                for _ in 0..$rounds {
                    self.0.keccakf()
                }
            }
        }

        #[derive(Clone, Debug)]
        pub struct $name(pub(crate) State);

        impl Default for $name {
            fn default() -> Self {
                Self(State::zero())
            }
        }

        impl BlockInput for $name {
            type BlockSize = bits_to_bytes!($blocksize);
        }

        impl Input for $name {
            fn input(&mut self, input: &[u8]) {
                unimplemented!()
            }
        }

        impl FixedOutput for $name {
            type OutputSize = bits_to_bytes!($outputsize);

            fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
                unimplemented!()
            }
        }
    }
}

mod sha3 {
 // impl_hash_function!(name, blocksize, capacity, rate, rounds, outputsize)
    impl_hash_function!(Sha3_224, 1600,  448, 1600 -  448, 24, 224);
    impl_hash_function!(Sha3_256, 1600,  512, 1600 -  512, 24, 256);
    impl_hash_function!(Sha3_384, 1600,  768, 1600 -  768, 24, 384);
    impl_hash_function!(Sha3_512, 1600, 1024, 1600 - 1024, 24, 512);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let hash = sha3::Sha3_256::default();

        assert!(hash);
    }
}

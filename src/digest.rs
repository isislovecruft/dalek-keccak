// -*- mode: rust; coding: utf-8; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2018 Henry de Valence, isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

use digest_external::BlockInput;
use digest_external::Input;
use digest_external::FixedOutput;

pub use digest_external::Digest;

use generic_array::ArrayLength;
use generic_array::typenum::{U28, U32, U48, U56, U64, U96, U128, U200};

use State;

pub trait Padding {
    fn pad(x: usize, m: &[u8]) -> Vec<u8>;
}

pub struct PadOneZeroStarOne{ }

impl Padding for PadOneZeroStarOne {
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
    fn squeeze(&mut self, length: Option<usize>) -> Vec<u8>;
}

macro_rules! bits_to_bytes {
    // Sizes for blocks and outputs
    (224)  => {U28};
    (256)  => {U32};
    (384)  => {U48};
    (512)  => {U64};

    // Sizes for keccak rates and capacities
    (448)  => {U56};
    (576)  => {U72};
    (768)  => {U96};
    (832)  => {U104};
    (1024) => {U128};
    (1088) => {U136};
    (1152) => {U144};
    (1344) => {U168};
    (1600) => {U200};
}

macro_rules! impl_sponge {
    ( $name:ident,
      $rate:expr,
      $outputsize:expr,
      $separator:expr
    ) => {
        impl Sponge for $name {
            type Pad = PadOneZeroStarOne;
            type Rate = bits_to_bytes!($rate);

            fn absorb(&mut self, input: &[u8]) {
                let p: Vec<u8> = Self::Pad::pad(input);
                let n: usize = p.len() - ($rate as usize);
                let c: usize = 6100usize - ($rate as usize);
                
                for chunk in p.exact_chunks($rate) {
                    for i in 0..$rate {
                        self.0[i] ^= chunk[i];
                    }
                }
                let z: Vec<u8> = p.truncate($rate);

                self.0.keccakf()
            }

            fn squeeze(&mut self, length: Option<usize>) {
                let d: usize = length.unwrap_or($outputsize as usize);
                
                
            }
        }
    }
}

macro_rules! impl_hash {
    ( $name:ident,
      $capacity:expr,
      $rate:expr,
      $outputsize:expr,
      $separator:expr
    ) => {
        impl_sponge!($name, $rate, $outputsize, $separator);

        #[derive(Clone, Debug)]
        pub struct $name(pub(crate) State);

        impl Default for $name {
            fn default() -> Self {
                Self(State::zero())
            }
        }

        impl BlockInput for $name {
            type BlockSize = bits_to_bytes!(1600);
        }

        impl Input for $name {
            fn process(&mut self, input: &[u8]) {
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

pub mod sha3 {
    use super::*;

 // impl_hash!(name, capacity, rate, rounds, outputsize, separator)
    //impl_hash!(Sha3_224,  448, (1600 -  448)/8, 224, 0x06);
    //impl_hash!(Sha3_256,  512, (1600 -  512)/8, 256, 0x06);
    //impl_hash!(Sha3_384,  768, (1600 -  768)/8, 384, 0x06);
    //impl_hash!(Sha3_512, 1024, (1600 - 1024)/8, 512, 0x06);

    #[derive(Clone, Debug)]
    pub struct Sha3_256(pub(crate) State);

    impl Default for Sha3_256 {
        fn default() -> Self {
            Sha3_256(State::zero())
        }
    }

    impl Sponge for Sha3_256 {
        type Pad = PadOneZeroStarOne;
        type Rate = bits_to_bytes!(1088);

        fn absorb(&mut self, input: &[u8]) {
            let p: Vec<u8> = Self::Pad::pad(input);
            let n: usize = p.len() - (1088/8 as usize);
            let c: usize = 1600usize/8 - (1088/8 as usize);
                
            for chunk in p.exact_chunks(1088/8) {
                for i in 0..1088/8 {
                    self.0[i] ^= chunk[i];
                }
            }
            p.truncate(1088/8);

            self.0.keccakf()
        }

        fn squeeze(&mut self, length: Option<usize>) -> Vec<u8> {
            let d: usize = length.unwrap_or(256 as usize);
            
            unimplemented!()
        }
    }

    impl BlockInput for Sha3_256 {
        type BlockSize = bits_to_bytes!(1600);
    }

    impl Input for Sha3_256 {
        fn process(&mut self, input: &[u8]) {
            unimplemented!()
        }
    }

    impl FixedOutput for Sha3_256 {
        type OutputSize = bits_to_bytes!(256);

        fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
            unimplemented!()
        }
    }
}

// separator for shake is 0x1F and for cshake is 0x04

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let hash = sha3::Sha3_256::default();

        assert!(hash);
    }
}

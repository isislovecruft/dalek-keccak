//! `Digest`-compatible implementations of SHA3.

use std::default::Default;

use digest::generic_array::typenum::{U136, U32};
use digest::generic_array::GenericArray;
use digest::{BlockInput, FixedOutput, Input};

pub use digest::Digest;

use keccak;

// pub struct Sha3_256 {
//     st: keccak::State,
//     pos: usize,
// }
// 
// impl Default for Sha3_256 {
//     fn default() -> Sha3_256 {
//         Sha3_256 {
//             st: keccak::State::default(),
//             pos: 0,
//         }
//     }
// }
// 
// impl Input for Sha3_256 {
//     fn process(&mut self, input: &[u8]) {
//         let rate = 136;
// 
//         for byte in input {
//             self.st[self.pos] ^= byte;
//             self.pos += 1;
//             if self.pos >= rate {
//                 self.st.keccakf();
//                 self.pos = 0;
//             }
//         }
//     }
// }
// 
// impl FixedOutput for Sha3_256 {
//     type OutputSize = U32;
// 
//     fn fixed_result(mut self) -> GenericArray<u8, U32> {
//         let rate = 136;
// 
//         self.st[self.pos] ^= 0x06;
//         self.st[rate - 1] ^= 0x80;
//         self.st.keccakf();
// 
//         let mut digest = GenericArray::default();
//         for i in 0..32 {
//             digest[i] = self.st[i];
//         }
// 
//         digest
//     }
// }
// 
// impl BlockInput for Sha3_256 {
//     type BlockSize = U136;
// }

#[macro_use]
use macros::*;

use digest::generic_array::typenum::{U32, U136};

//impl_hash!(Sha3_224, 144, 28);
impl_hash!(Sha3_256, U136, U32, 136, 32);
//impl_hash!(Sha3_384, 104, 48);
//impl_hash!(Sha3_512,  72, 64);

#[cfg(test)]
mod tests {
    use super::Digest;

    #[test]
    fn self_vs_sha3_crate() {
        use std::iter;

        // AAAAAAAAAAAAAAAAAAAAAAAAA
        let msg = iter::repeat(65).take(2000).collect::<Vec<u8>>();

        let mut ours = super::Sha3_256::default();
        let mut theirs = ::sha3::Sha3_256::default();

        ours.input(&msg);
        theirs.input(&msg);

        assert_eq!(ours.result(), theirs.result());
    }
}

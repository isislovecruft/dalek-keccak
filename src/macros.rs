
use digest::generic_array::typenum::{U28, U32, U48, U64, U72, U104, U136, U144};
use digest::generic_array::GenericArray;
use digest::{BlockInput, FixedOutput, Input};

use keccak;

trace_macros!(true);

#[macro_export]
macro_rules! to_typenum {
    (28)  => {U28};
    (32)  => {U32};
    (48)  => {U48};
    (64)  => {U64};
    (72)  => {U72};
    (104) => {U104};
    (136) => {U136};
    (144) => {U144};
}

#[macro_export]
macro_rules! impl_hash {
    ( 
        $name:ident,
        $rate:ty,
        $size:ty,
        $ratebytes:expr,
        $sizebytes:expr
    ) => {

        pub struct $name {
            state: keccak::State,
            position: usize,
        }

        impl Default for $name {
            fn default() -> $name {
                $name {
                    state: keccak::State::default(),
                    position: 0,
                }
            }
        }

        impl Input for $name {
            fn process(&mut self, input: &[u8]) {
                let rate = $ratebytes;

                for byte in input {
                    self.state[self.position] ^= byte;
                    self.position += 1;

                    if self.position >= rate {
                        self.state.keccakf();
                        self.position = 0;
                    }
                }
            }
        }

        impl FixedOutput for $name {
            type OutputSize = $size;

            fn fixed_result(mut self) -> GenericArray<u8, $size> {
                let rate = $ratebytes;

                self.state[self.position] ^= 0x06;
                self.state[rate - 1] ^= 0x80;
                self.state.keccakf();

                let mut digest = GenericArray::default();

                for i in 0..$sizebytes {
                    digest[i] = self.state[i];
                }

                digest
            }
        }

        impl BlockInput for $name {
            type BlockSize = $rate;
        }
    }
}

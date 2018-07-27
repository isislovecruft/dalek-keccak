use std::fmt;
use std::ops::{Index, IndexMut};

const ROTATION_CONSTANTS: [[u32; 5]; 5] = [
    [00, 01, 62, 28, 27],
    [36, 44, 06, 55, 20],
    [03, 10, 43, 25, 39],
    [41, 45, 15, 21, 08],
    [18, 02, 61, 56, 14],
];

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

#[derive(Clone)]
pub struct State([[u64; 5]; 5]);

impl fmt::Debug for State {
    #[allow(non_snake_case)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "keccak state:")?;
        let A = self.0;
        writeln!(f, "[")?;
        for i in 0..5 {
            writeln!(
                f,
                "[{:016X}, {:016X}, {:016X}, {:016X}, {:016X}],",
                A[i][0], A[i][1], A[i][2], A[i][3], A[i][4],
            )?;
        }
        writeln!(f, "]")?;
        Ok(())
    }
}

impl Index<usize> for State {
    type Output = u8;
    #[inline]
    fn index(&self, index: usize) -> &u8 {
        let bytes: &[u8; 5 * 5 * 8] = unsafe { ::std::mem::transmute(&self.0) };

        &bytes[index]
    }
}

impl IndexMut<usize> for State {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        let bytes: &mut [u8; 5 * 5 * 8] = unsafe { ::std::mem::transmute(&mut self.0) };

        &mut bytes[index]
    }
}

impl State {
    pub fn keccakf(&mut self) {
        for &rc in &ROUND_CONSTANTS {
            self.round(rc)
        }
    }

    // without inline(never), inlining the round function into the
    // keccakf callsite causes a copy of the entire state, possibly
    // because of nested &mut self...
    #[inline(never)]
    #[allow(non_snake_case)]
    fn round(&mut self, rc: u64) {
        let A = &mut self.0;

        // θ step
        let C: [u64; 5] = [
            A[0][0] ^ A[1][0] ^ A[2][0] ^ A[3][0] ^ A[4][0],
            A[0][1] ^ A[1][1] ^ A[2][1] ^ A[3][1] ^ A[4][1],
            A[0][2] ^ A[1][2] ^ A[2][2] ^ A[3][2] ^ A[4][2],
            A[0][3] ^ A[1][3] ^ A[2][3] ^ A[3][3] ^ A[4][3],
            A[0][4] ^ A[1][4] ^ A[2][4] ^ A[3][4] ^ A[4][4],
        ];

        let D: [u64; 5] = [
            C[4] ^ (C[1].rotate_left(1)),
            C[0] ^ (C[2].rotate_left(1)),
            C[1] ^ (C[3].rotate_left(1)),
            C[2] ^ (C[4].rotate_left(1)),
            C[3] ^ (C[0].rotate_left(1)),
        ];

        for y in 0..5 {
            A[y] = [
                A[y][0] ^ D[0],
                A[y][1] ^ D[1],
                A[y][2] ^ D[2],
                A[y][3] ^ D[3],
                A[y][4] ^ D[4],
            ];
        }

        // ρ and π steps
        let B_ij = |x: usize, y: usize| A[y][x].rotate_left(ROTATION_CONSTANTS[y][x]);

        let B: [[u64; 5]; 5] = [
            [B_ij(0, 0), B_ij(1, 1), B_ij(2, 2), B_ij(3, 3), B_ij(4, 4)],
            [B_ij(3, 0), B_ij(4, 1), B_ij(0, 2), B_ij(1, 3), B_ij(2, 4)],
            [B_ij(1, 0), B_ij(2, 1), B_ij(3, 2), B_ij(4, 3), B_ij(0, 4)],
            [B_ij(4, 0), B_ij(0, 1), B_ij(1, 2), B_ij(2, 3), B_ij(3, 4)],
            [B_ij(2, 0), B_ij(3, 1), B_ij(4, 2), B_ij(0, 3), B_ij(1, 4)],
        ];

        // χ step
        for y in 0..5 {
            A[y][0] = B[y][0] ^ ((!B[y][1]) & B[y][2]);
            A[y][1] = B[y][1] ^ ((!B[y][2]) & B[y][3]);
            A[y][2] = B[y][2] ^ ((!B[y][3]) & B[y][4]);
            A[y][3] = B[y][3] ^ ((!B[y][4]) & B[y][0]);
            A[y][4] = B[y][4] ^ ((!B[y][0]) & B[y][1]);
        }

        // ι step
        A[0][0] ^= rc;
    }

    pub(crate) fn zero() -> State {
        State([[0; 5]; 5])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_on_zero_state() {
        // https://github.com/gvanas/KeccakCodePackage/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt
        //
        // This is the state obtained by applying the keccakf to the
        // zero state.
        let expected = State([
            [
                0xF1258F7940E1DDE7,
                0x84D5CCF933C0478A,
                0xD598261EA65AA9EE,
                0xBD1547306F80494D,
                0x8B284E056253D057,
            ],
            [
                0xFF97A42D7F8E6FD4,
                0x90FEE5A0A44647C4,
                0x8C5BDA0CD6192E76,
                0xAD30A6F71B19059C,
                0x30935AB7D08FFC64,
            ],
            [
                0xEB5AA93F2317D635,
                0xA9A6E6260D712103,
                0x81A57C16DBCF555F,
                0x43B831CD0347C826,
                0x01F22F1A11A5569F,
            ],
            [
                0x05E5635A21D9AE61,
                0x64BEFEF28CC970F2,
                0x613670957BC46611,
                0xB87C5A554FD00ECB,
                0x8C3EE88A1CCF32C8,
            ],
            [
                0x940C7922AE3A2614,
                0x1841F924A2C509E4,
                0x16F53526E70465C2,
                0x75F644E97F30A13B,
                0xEAF1FF7B5CECA249,
            ],
        ]);

        let mut zero = State([[0; 5]; 5]);
        zero.keccakf();

        assert_eq!(zero.0, expected.0);
    }
}

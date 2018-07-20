use std::fmt;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_rounds_on_zero_input() {
        let mut st = State([[0u64; 5]; 5]);

        println!("initial state");
        println!("{:?}", st);

        for i in 0..24 {
            st.round(ROUND_CONSTANTS[i]);
            println!("after round {}", i);
            println!("{:?}", st);
        }
    }
}

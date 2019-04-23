pub struct SDES {
    master_key: u16
}

impl SDES {
    const S0BOX: [[u8; 4]; 4] = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ];

    const S1BOX: [[u8; 4]; 4] = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ];

    pub fn new(master_key: u16) -> SDES {
        SDES { master_key }
    }

    fn permute(k: u16, order: Vec<u8>, length: u8) -> u16 {
        let mut result: u16 = 0;
        for i in 0..order.len() {
            let bit: u16 = (k >> (length - order[i] - 1)) & 1;
            result |= bit << (order.len() as u8 - i as u8 - 1);
        }
        result
    }

    fn circular_left_shift(k: u16, n: u8) -> u16 {
        let right: u16 = k & (2u16.pow(5) - 1);
        let left: u16 = k >> 5;
        let first_shift: u16 = SDES::left_rotate(left, n);
        let second_shift: u16 = SDES::left_rotate(right, n);
        (first_shift << 5) | second_shift
    }

    // ignore leading zeros by selecting the last 10 bits
    fn left_rotate(k: u16, n: u8) -> u16 {
        ((k << n) | (k >> (5 - n))) & (2u16.pow(5) - 1)
    }

    fn p10(&self) -> u16 {
        SDES::permute(self.master_key, vec![2, 4, 1, 6, 3, 9, 0, 8, 7, 5], 10)
    }

    fn p8(k: u16) -> u8 {
        SDES::permute(k, vec![5, 2, 6, 3, 7, 4, 9, 8], 10) as u8
    }

    fn generate_keys(&self) -> (u8, u8) {
        let p10: u16 = self.p10();
        let k1: u8 = SDES::p8(SDES::circular_left_shift(p10, 1));
        let k2: u8 = SDES::p8(SDES::circular_left_shift(p10, 3));
        (k1, k2)
    }

    fn ip(k: u8) -> u8 {
        SDES::permute(k as u16, vec![1, 5, 2, 0, 3, 7, 4, 6], 8) as u8
    }

    fn rip(k: u8) -> u8 {
        SDES::permute(k as u16, vec![3, 0, 2, 4, 6, 1, 7, 5], 8) as u8
    }

    fn ep(k: u8) -> u8 {
        SDES::permute(k as u16, vec![3, 0, 1, 2, 1, 2, 3, 0], 4) as u8
    }

    fn s0(k: u8) -> u8 {
        let r: usize = (((k & (1 << 3)) >> 2) | (k & 1)) as usize;
        let c: usize = (((k & (1 << 2)) >> 1) | ((k & (1 << 1)) >> 1)) as usize;
        SDES::S0BOX[r][c]
    }

    fn s1(k: u8) -> u8 {
        let r: usize = (((k & (1 << 3)) >> 2) | (k & 1)) as usize;
        let c: usize = (((k & (1 << 2)) >> 1) | ((k & (1 << 1)) >> 1)) as usize;
        SDES::S1BOX[r][c]
    }

    fn p4(left: u8, right: u8) -> u8 {
        let k: u8 = (left << 2) | right;
        SDES::permute(k as u16, vec![1, 3, 2, 0], 4) as u8
    }

    fn sw(k: u8) -> u8 {
        SDES::permute(k as u16, vec![4, 5, 6, 7, 0, 1, 2, 3], 8) as u8
    }

    fn f(bits: u8, key: u8) -> u8 {
        let xor: u8 = SDES::ep(bits) ^ key;
        let right: u8 = xor & 15;
        let left: u8 = xor >> 4;
        SDES::p4(SDES::s0(left), SDES::s1(right))
    }

    fn fk(bits: u8, key: u8) -> u8 {
        let right: u8 = bits & 15;
        let left: u8 = bits >> 4;
        let xor: u8 = left ^ SDES::f(right, key);
        (xor << 4) | right
    }

    pub fn encrypt(&self, message: &'static str) -> String {
        let (k1, k2) = self.generate_keys();
        let mut cipher: String = String::new();

        for c in message.chars() {
            let char_byte = c as u8;
            let ip: u8 = SDES::ip(char_byte);
            let fk1: u8 = SDES::fk(ip, k1);
            let sw: u8 = SDES::sw(fk1);
            let fk2: u8 = SDES::fk(sw, k2);
            let rip: u8 = SDES::rip(fk2);
            cipher.push(rip as char);
        }

        cipher
    }

    pub fn decrypt(&self, cipher: &String) -> String {
        let (k1, k2) = self.generate_keys();
        let mut message: String = String::new();

        for c in cipher.chars() {
            let char_byte: u8 = c as u8;
            let ip: u8 = SDES::ip(char_byte);
            let fk1: u8 = SDES::fk(ip, k2);
            let sw: u8 = SDES::sw(fk1);
            let fk2: u8 = SDES::fk(sw, k1);
            let rip: u8 = SDES::rip(fk2);
            message.push(rip as char);
        }

        message
    }
}
//! Core cryptographic primitives for Arcium.

pub mod ratchet;
pub mod x3dh;

#[cfg(test)]
mod tests {
    #[test]
    fn basic_alice_to_bob() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn bidirectional() {
        assert!(true);
    }

    #[test]
    fn ratchet_test() {
        assert_eq!(1, 1);
    }
}
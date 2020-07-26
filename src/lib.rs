#![cfg_attr(not(feature = "std"), no_std)]
#[allow(clippy::many_single_char_names)]
mod math;
#[allow(clippy::many_single_char_names)]
pub mod rsa;

#[cfg(test)]
mod tests {
    use crate::rsa::RSA;
    use num_bigint::BigInt;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

extern crate num_traits;

use core::ops::{Mul, Sub};

use num_bigint::BigInt;
use num_integer::Integer;

use crate::math::mod_inverse;

pub struct RSAPublicKey {
    pub n: BigInt,
    pub e: BigInt,
}

pub struct RSAPrivateKey {
    pub n: BigInt,
    pub d: BigInt,
}

pub struct RSA;

impl RSA {
    pub fn new_key_pair() -> (RSAPublicKey, RSAPrivateKey) {
        let p = BigInt::from(61);
        let q = BigInt::from(53);

        let n = p.clone().mul(&q);

        let p_minus_one: BigInt = p.sub(1);
        let q_minus_one: BigInt = q.sub(1);

        let lambda: BigInt = p_minus_one.lcm(&q_minus_one);

        let e = BigInt::from(17);

        let d = mod_inverse(&e, &lambda).expect("Cannot compute mod_inverse");

        let public_key = RSAPublicKey {
            n: n.clone(),
            e,
        };

        let private_key = RSAPrivateKey {
            n,
            d,
        };

        (public_key, private_key)
    }

    pub fn encrypt(message: &BigInt, public_key: &RSAPublicKey) -> BigInt {
        message.modpow(&public_key.e, &public_key.n)
    }

    pub fn decrypt(cipher_text: &BigInt, private_key: &RSAPrivateKey) -> BigInt {
        BigInt::modpow(cipher_text, &private_key.d, &private_key.n)
    }
}


#[cfg(test)]
mod tests {
    use num_bigint::BigInt;

    use super::*;

    #[test]
    fn key_pair() {
        let (public_key, private_key) = RSA::new_key_pair();

        assert_eq!(public_key.n, BigInt::from(3233));
        assert_eq!(public_key.e, BigInt::from(17));
        assert_eq!(private_key.d, BigInt::from(413));
    }

    #[test]
    fn encrypt() {
        let (public_key, _) = RSA::new_key_pair();

        let original_message = BigInt::from(65);
        let cipher_text = RSA::encrypt(&original_message, &public_key);
        assert_eq!(cipher_text, BigInt::from(2790));
    }

    #[test]
    fn decrypt() {
        let (_, private_key) = RSA::new_key_pair();

        let original_message = BigInt::from(65);
        let cipher_text = &BigInt::from(2790);
        let message = RSA::decrypt(cipher_text, &private_key);
        assert_eq!(message, original_message);
    }

    #[test]
    fn encrypt_decrypt() {
        let (public_key, private_key) = RSA::new_key_pair();

        let original_message = BigInt::from(65);
        let cipher_text = RSA::encrypt(&original_message, &public_key);
        let message = RSA::decrypt(&cipher_text, &private_key);

        assert_eq!(cipher_text, BigInt::from(2790));
        assert_eq!(message, BigInt::from(65));
    }
}
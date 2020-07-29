use core::ops::Mul;

use num_bigint::BigInt;
use num_traits::{Signed, Zero};

pub struct ElGamalPublicKey {
    pub params: ElGamalParameters,
    pub h: BigInt,
}

pub struct ElGamalPrivateKey {
    pub params: ElGamalParameters,
    pub x: BigInt,
}

#[derive(Clone)]
pub struct ElGamalParameters {
    /// Modulus
    pub p: BigInt,

    /// Generator
    pub g: BigInt,
}

impl ElGamalParameters {
    /// Determines whether the given value belongs to the group Z_p
    pub fn belongs_to_group(&self, value: &BigInt) -> bool {
        value.is_positive() && value < &self.p
    }
}

impl ElGamalPublicKey {
    pub fn new(private_key: &ElGamalPrivateKey) -> Self {
        let h = private_key
            .params
            .g
            .modpow(&private_key.x, &private_key.params.p);
        ElGamalPublicKey {
            h,
            params: private_key.params.clone(),
        }
    }
}

impl ElGamalPrivateKey {
    pub fn new(x: BigInt, params: ElGamalParameters) -> Self {
        assert!(params.belongs_to_group(&x));

        ElGamalPrivateKey { params, x }
    }

    pub fn extract_public_key(&self) -> ElGamalPublicKey {
        ElGamalPublicKey::new(self)
    }
}

pub struct ElGamal;

/// Exponential ElGamal encryption scheme
impl ElGamal {
    /// To keep the function easily portable to the BC/no_std ecosystem, the nonce is injected into the algorithm.
    pub fn encrypt(
        message: BigInt,
        nonce: BigInt,
        public_key: &ElGamalPublicKey,
    ) -> (BigInt, BigInt) {
        assert!(public_key.params.belongs_to_group(&nonce));

        let modulus = public_key.params.p.clone();
        let generator = public_key.params.g.clone();

        let c = generator.modpow(&nonce, &modulus);
        let public_key_to_nonce = public_key.h.modpow(&nonce, &modulus);
        let g_to_m = generator.modpow(&message, &modulus);
        let d = g_to_m.mul(public_key_to_nonce) % modulus;
        (c, d)
    }

    pub fn decrypt(cipher: (BigInt, BigInt), private_key: &ElGamalPrivateKey) -> BigInt {
        let (c, d) = cipher;

        let modulus = private_key.params.p.clone();
        let sk = private_key.x.clone();
        let exponent = (modulus.clone() - sk - 1) % modulus.clone();

        let generator = private_key.params.g.clone();

        let g_to_m = c.modpow(&exponent, &modulus).mul(d) % modulus.clone();
        let mut i = BigInt::zero();

        loop {
            let target = generator.clone().modpow(&i, &modulus.clone());

            if target.eq(&g_to_m) {
                return i;
            }

            i += 1;

            if i > private_key.params.p.clone() {
                panic!("Failed to find exponent!")
            }
        }
    }

    pub fn add(cipher1: (BigInt, BigInt), cipher2: (BigInt, BigInt)) -> (BigInt, BigInt) {
        let (c1, d1) = cipher1;
        let (c2, d2) = cipher2;
        (c1 * c2, d1 * d2)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use num_traits::Num;

    use super::*;

    #[test]
    fn derive_pubkey_from_private() {
        let params = ElGamalParameters {
            p: BigInt::from(283),
            g: BigInt::from(60),
        };

        let private_key = ElGamalPrivateKey::new(BigInt::from(7), params.clone());
        let public_key = ElGamalPublicKey::new(&private_key);

        assert_eq!(public_key.h, BigInt::from(216));
        assert_eq!(private_key.extract_public_key().h, BigInt::from(216));
    }

    #[test]
    #[should_panic]
    fn encrypt_nonce_invalid() {
        let params = ElGamalParameters {
            p: BigInt::from(283),
            g: BigInt::from(60),
        };

        let public_key = ElGamalPublicKey {
            h: BigInt::from(216),
            params: params.clone(),
        };

        let nonce = BigInt::from(params.p + 1);
        let message = BigInt::from(101);
        ElGamal::encrypt(message, nonce, &public_key);
    }

    #[test]
    fn encrypt_decrypt() {
        let message = BigInt::from(88);
        let params = ElGamalParameters {
            p: BigInt::from(2753),
            g: BigInt::from(1035),
        };

        let private_key = ElGamalPrivateKey::new(BigInt::from(174), params.clone());
        let public_key = private_key.extract_public_key();

        let c = ElGamal::encrypt(message.clone(), BigInt::from(3), &public_key);
        let recovered_message = ElGamal::decrypt(c, &private_key);
        assert_eq!(recovered_message, message);
    }

    #[test]
    fn encrypt_decrypt_additive_property() {
        let m1 = BigInt::from(88);
        let m2 = BigInt::from(42);
        let sum = m1.clone() + m2.clone();

        let params = ElGamalParameters {
            // 2048-bit size key
            p: BigInt::from_str_radix("F52E0A34AA46657BE51CE1BFEA30D0BE7FD65D879AB9B2CAD7CDFECE734F074065869ABFD3B9FF77C77ACCE7824F75BB51D8BC0A2D83974D3CFE14100375C9DE52C4C038FDD03B4BC30616EE1997E7D5AB108DA95BEC7B7D5394781B2CE85000D8A7A02306ED48F7242D0277A8EE0DF0ABAC3725A9349FA4F1883D89FD5A027D97670368369B266F4BCDD1D4F266303580003FC02B82B97B86674D7387083143583ACA5C5AA63A86D6C88CF95F203203DCFE726C0098790B2B64AE3DD58ACDFDB912A75688B593F9D1342D49408ACAE04B184DA61976FCBF87F0A608CBC7F7B152D57C0F2F1E090A55EFA74E49BDCABEEF9A59EC9BD3D89FC8BBD920D5CA1CED", 16).unwrap(),
            g: BigInt::from(1035),
        };

        let private_key = ElGamalPrivateKey::new(BigInt::from(174), params.clone());
        let public_key = private_key.extract_public_key();

        let cipher1 = ElGamal::encrypt(m1.clone(), BigInt::from(3), &public_key);
        let cipher2 = ElGamal::encrypt(m2.clone(), BigInt::from(7), &public_key);
        let encrypted_sum = ElGamal::add(cipher1, cipher2);

        let recovered_message = ElGamal::decrypt(encrypted_sum, &private_key);
        assert_eq!(recovered_message, sum);
    }
}

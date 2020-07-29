use core::ops::Mul;

use num_bigint::BigInt;
use num_traits::Zero;

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

    /// Order
    pub q: BigInt,

    /// Generator
    pub g: BigInt,
}

impl ElGamalPublicKey {
    pub fn new(private_key: &ElGamalPrivateKey) -> Self {
        let h = private_key.params.g.modpow(&private_key.x, &private_key.params.p);
        ElGamalPublicKey {
            h,
            params: private_key.params.clone(),
        }
    }
}

impl ElGamalPrivateKey {
    pub fn new(x: BigInt, params: ElGamalParameters) -> Self {
        assert!(x < params.q);
        ElGamalPrivateKey {
            params,
            x,
        }
    }
}

pub struct ElGamal;

/// Exponential ElGamal encryption scheme
impl ElGamal {
    /// To keep the function easily portable to the BC/no_std ecosystem, the nonce is injected into the algorithm.
    pub fn encrypt(message: BigInt, nonce: BigInt, public_key: ElGamalPublicKey) -> (BigInt, BigInt) {
        assert!(nonce < public_key.params.q);

        let modulus = public_key.params.p.clone();
        let generator = public_key.params.g.clone();

        let c = generator.modpow(&nonce, &modulus);
        let public_key_to_nonce = public_key.h.modpow(&nonce, &modulus);
        //let d = generator.clone().modpow(&message, &modulus);
        let d = message.mul(public_key_to_nonce) % modulus;
        (c, d)
    }

    pub fn decrypt(cipher: (BigInt, BigInt), private_key: ElGamalPrivateKey) -> BigInt {
        let (c, d) = cipher;

        let modulus = private_key.params.p.clone();
        let sk = private_key.x.clone();
        let exponent = (modulus.clone() - sk - 1) % modulus.clone();
        c.modpow(&exponent, &modulus).mul(d.clone()) % modulus
    }

}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;

    use super::*;

    #[test]
    fn derive_pubkey_from_private() {
        let params = ElGamalParameters {
            p: BigInt::from(283),
            q: BigInt::from(47),
            g: BigInt::from(60),
        };

        let private_key = ElGamalPrivateKey::new(BigInt::from(7), params.clone());
        let public_key = ElGamalPublicKey::new(&private_key);

        assert_eq!(public_key.h, BigInt::from(216));
    }

    #[test]
    fn encrypt() {
        let params = ElGamalParameters {
            p: BigInt::from(283),
            q: BigInt::from(47),
            g: BigInt::from(60),
        };

        let public_key = ElGamalPublicKey {
            h: BigInt::from(216),
            params: params.clone(),
        };

        let nonce = BigInt::from(36);
        let message = BigInt::from(101);
        let (c, d) = ElGamal::encrypt(message, nonce, public_key);

        assert_eq!(c, BigInt::from(78));
        assert_eq!(d, BigInt::from(218));
    }

    #[test]
    #[should_panic]
    fn encrypt_nonce_invalid() {
        let params = ElGamalParameters {
            p: BigInt::from(283),
            q: BigInt::from(47),
            g: BigInt::from(60),
        };

        let public_key = ElGamalPublicKey {
            h: BigInt::from(216),
            params: params.clone(),
        };

        let nonce = BigInt::from(params.q + 1);
        let message = BigInt::from(101);
        ElGamal::encrypt(message, nonce, public_key);
    }

    #[test]
    fn decrypt() {
        let params = ElGamalParameters {
            p: BigInt::from(283),
            q: BigInt::from(47),
            g: BigInt::from(60),
        };

        let private_key = ElGamalPrivateKey::new(BigInt::from(7), params.clone());

        let c = BigInt::from(78);
        let d = BigInt::from(218);

        let recovered_message = ElGamal::decrypt((c, d), private_key);

        let message = BigInt::from(101);
        assert_eq!(message, recovered_message);
    }
}
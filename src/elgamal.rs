use alloc::vec::Vec;
use core::ops::{Div, Mul, Sub};

use num_bigint::BigInt;
use num_traits::Signed;

use crate::math;
use crate::math::mod_div;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Cipher(pub BigInt, pub BigInt);

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ElGamalPublicKey {
    pub params: ElGamalParameters,
    pub h: BigInt,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ElGamalPrivateKey {
    pub params: ElGamalParameters,
    pub x: BigInt,
}

#[derive(Clone, Eq, PartialEq, Debug)]
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

    pub fn q(&self) -> BigInt {
        (self.p.clone().sub(1 as i32)).div(2)
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

    pub fn combine(&self, other: &ElGamalPublicKey) -> Self {
        ElGamalPublicKey {
            h: &self.h * &other.h % &self.params.p,
            params: self.params.clone(),
        }
    }

    pub fn combine_multiple_vec(keys: Vec<ElGamalPublicKey>) -> Self {
        assert!(!keys.is_empty());
        let params = keys[0].params.clone();
        let mut h = BigInt::from(1);
        keys.iter().for_each(|key| h *= &key.h);
        h %= &params.p;

        ElGamalPublicKey { h, params }
    }

    pub fn combine_multiple(&self, others: &[&ElGamalPublicKey]) -> Self {
        assert!(!others.is_empty());

        let mut h = self.h.clone();
        for share in others.iter() {
            h *= &share.h;
        }
        let params = self.params.clone();
        h %= &params.p;

        ElGamalPublicKey { h, params }
    }
}

impl ElGamalPrivateKey {
    pub fn new(x: &BigInt, params: ElGamalParameters) -> Self {
        assert!(params.belongs_to_group(x));

        ElGamalPrivateKey {
            params,
            x: x.clone(),
        }
    }

    pub fn extract_public_key(&self) -> ElGamalPublicKey {
        ElGamalPublicKey::new(self)
    }
}

pub struct ElGamal;

/// Exponential ElGamal encryption scheme
impl ElGamal {
    /// To keep the function easily portable to the BC/no_std ecosystem, the nonce is injected into the algorithm.
    pub fn encrypt(message: &BigInt, nonce: &BigInt, public_key: &ElGamalPublicKey) -> Cipher {
        assert!(
            public_key.params.belongs_to_group(nonce),
            "Nonce too big: {}",
            nonce.to_str_radix(16)
        );

        let modulus = &public_key.params.p;
        let generator = &public_key.params.g;

        let c = generator.modpow(&nonce, &modulus);
        let public_key_to_nonce = public_key.h.modpow(nonce, modulus);
        let g_to_m = generator.modpow(message, modulus);
        let d = g_to_m.mul(public_key_to_nonce) % modulus;
        Cipher(c, d)
    }

    pub fn decrypt(cipher: &Cipher, private_key: &ElGamalPrivateKey) -> BigInt {
        let Cipher(c, d) = cipher;

        let modulus = private_key.params.p.clone();
        let sk = private_key.x.clone();

        let generator = private_key.params.g.clone();
        let c_to_sk = c.modpow(&sk, &modulus);
        let g_to_m = math::mod_div(&d, &c_to_sk, &modulus).expect("Cannot find mod inverse");

        math::brute_force_dlog(&g_to_m, &generator, &modulus)
    }

    pub fn add(cipher1: &Cipher, cipher2: &Cipher, params: &ElGamalParameters) -> Cipher {
        let Cipher(c1, d1) = cipher1;
        let Cipher(c2, d2) = cipher2;
        Cipher(c1 * c2 % &params.p, d1 * d2 % &params.p)
    }

    pub fn add_many(ciphers: Vec<Cipher>, params: &ElGamalParameters) -> Cipher {
        let mut c = BigInt::from(1);
        let mut d = BigInt::from(1);
        for cipher in ciphers.iter() {
            c *= &cipher.0;
            d *= &cipher.1;
        }

        c %= &params.p;
        d %= &params.p;

        Cipher(c, d)
    }

    pub fn sub(cipher1: &Cipher, cipher2: &Cipher, params: &ElGamalParameters) -> Cipher {
        let Cipher(c1, d1) = cipher1;
        let Cipher(c2, d2) = cipher2;
        let modulus = &params.p;
        Cipher(
            mod_div(c1, c2, modulus).unwrap(),
            mod_div(d1, d2, modulus).unwrap(),
        )
    }

    pub fn combine_shares(shares: &[&BigInt], params: &ElGamalParameters) -> BigInt {
        let mut product = BigInt::from(1);
        for &share in shares.iter() {
            product *= share;
        }

        product % &params.p
    }

    pub fn decrypt_share(cipher: &Cipher, private_key: &ElGamalPrivateKey) -> BigInt {
        let sk = &private_key.x;
        let modulus = &private_key.params.p;
        let Cipher(c, _) = cipher;
        c.modpow(sk, modulus)
    }

    pub fn decrypt_shares(
        cipher: &Cipher,
        decrypted_shares: &[&BigInt],
        params: &ElGamalParameters,
    ) -> BigInt {
        let d_product = Self::combine_shares(decrypted_shares, params);
        let Cipher(_, d) = cipher;

        let modulus = params.p.clone();

        let generator = params.g.clone();
        let g_to_m = math::mod_div(&d, &d_product, &modulus).expect("Cannot find mod inverse");

        math::brute_force_dlog(&g_to_m, &generator, &modulus)
    }
}

#[cfg(any(test, feature = "bench"))]
pub mod benchmark {
    use alloc::vec::Vec;

    use num_bigint::BigInt;
    use rayon::prelude::*;

    use crate::elgamal::{Cipher, ElGamal, ElGamalParameters, ElGamalPrivateKey};
    use crate::math::{benchmark::brute_force_dlog_with_heuristic, mod_div};

    impl ElGamal {
        pub fn add_parallel(ciphers: Vec<Cipher>, params: &ElGamalParameters) -> Cipher {
            let c = BigInt::from(1);
            let d = BigInt::from(1);
            let c = Cipher(c, d);
            let sum: Cipher = ciphers.par_iter().cloned().reduce(
                || c.clone(),
                |cipher1, cipher2| {
                    Cipher(
                        &cipher1.0 * &cipher2.0 % &params.p,
                        &cipher1.1 * &cipher2.1 % &params.p,
                    )
                },
            );

            sum
        }

        pub fn decrypt_with_heuristic(
            cipher: &Cipher,
            private_key: &ElGamalPrivateKey,
            upper_bound: u64,
        ) -> BigInt {
            let Cipher(c, d) = cipher;

            let modulus = private_key.params.p.clone();
            let sk = private_key.x.clone();

            let generator = private_key.params.g.clone();
            let c_to_sk = c.modpow(&sk, &modulus);
            let g_to_m = mod_div(&d, &c_to_sk, &modulus).expect("Cannot find mod inverse");

            brute_force_dlog_with_heuristic(&g_to_m, &generator, &modulus, upper_bound)
        }
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

        let private_key = ElGamalPrivateKey::new(&BigInt::from(7), params);
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

        let nonce = params.p + 1;
        let message = BigInt::from(101);
        ElGamal::encrypt(&message, &nonce, &public_key);
    }

    #[test]
    fn encrypt_decrypt() {
        let message = BigInt::from(88);
        let params = ElGamalParameters {
            p: BigInt::from(2753),
            g: BigInt::from(1035),
        };

        let private_key = ElGamalPrivateKey::new(&BigInt::from(174), params);
        let public_key = private_key.extract_public_key();

        let c = ElGamal::encrypt(&message, &BigInt::from(3), &public_key);
        let recovered_message = ElGamal::decrypt(&c, &private_key);
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

        let private_key = ElGamalPrivateKey::new(&BigInt::from(174), params.clone());
        let public_key = private_key.extract_public_key();

        let cipher1 = ElGamal::encrypt(&m1, &BigInt::from(3), &public_key);
        let cipher2 = ElGamal::encrypt(&m2, &BigInt::from(7), &public_key);
        let encrypted_sum = ElGamal::add(&cipher1, &cipher2, &params);

        let recovered_message = ElGamal::decrypt(&encrypted_sum, &private_key);
        assert_eq!(recovered_message, sum);

        let sub = ElGamal::sub(&encrypted_sum, &cipher1, &params);
        let recovered_message = ElGamal::decrypt(&sub, &private_key);
        assert_eq!(recovered_message, m2);
    }

    #[test]
    fn encrypt_decrypt_additive_property_zero_encryption() {
        let m1 = BigInt::from(88);

        let params = ElGamalParameters {
            // 2048-bit size modulus
            p: BigInt::from_str_radix("F52E0A34AA46657BE51CE1BFEA30D0BE7FD65D879AB9B2CAD7CDFECE734F074065869ABFD3B9FF77C77ACCE7824F75BB51D8BC0A2D83974D3CFE14100375C9DE52C4C038FDD03B4BC30616EE1997E7D5AB108DA95BEC7B7D5394781B2CE85000D8A7A02306ED48F7242D0277A8EE0DF0ABAC3725A9349FA4F1883D89FD5A027D97670368369B266F4BCDD1D4F266303580003FC02B82B97B86674D7387083143583ACA5C5AA63A86D6C88CF95F203203DCFE726C0098790B2B64AE3DD58ACDFDB912A75688B593F9D1342D49408ACAE04B184DA61976FCBF87F0A608CBC7F7B152D57C0F2F1E090A55EFA74E49BDCABEEF9A59EC9BD3D89FC8BBD920D5CA1CED", 16).unwrap(),
            g: BigInt::from(1035),
        };

        let private_key = ElGamalPrivateKey::new(&BigInt::from(174), params.clone());
        let public_key = private_key.extract_public_key();

        let cipher = ElGamal::encrypt(&m1, &BigInt::from(3), &public_key);
        let zero_encryption = ElGamal::encrypt(&BigInt::from(0), &BigInt::from(13), &public_key);
        let cipher_plus_zero = ElGamal::add(&cipher, &zero_encryption, &params);

        let recovered_message = ElGamal::decrypt(&cipher_plus_zero, &private_key);
        assert_ne!(cipher, cipher_plus_zero);
        assert_eq!(recovered_message, m1);
    }

    #[test]
    fn combine() {
        let params = ElGamalParameters {
            p: BigInt::from(2753),
            g: BigInt::from(1035),
        };

        let public_key1 = ElGamalPublicKey {
            h: BigInt::from(2),
            params: params.clone(),
        };

        let public_key2 = ElGamalPublicKey {
            h: BigInt::from(5),
            params: params.clone(),
        };

        let public_key3 = ElGamalPublicKey {
            h: BigInt::from(7),
            params: params.clone(),
        };

        let pk = public_key1.combine(&public_key2);

        assert_eq!(pk.h, BigInt::from(10));
        assert_eq!(pk.params, params);

        let pk = ElGamalPublicKey::combine(&public_key1, &public_key2);

        assert_eq!(pk.h, BigInt::from(10));
        assert_eq!(pk.params, params);

        let pk: ElGamalPublicKey = public_key1.combine_multiple(&[&public_key2, &public_key3]);

        assert_eq!(pk.h, BigInt::from(70));
        assert_eq!(pk.params, params);

        let pk: ElGamalPublicKey =
            ElGamalPublicKey::combine_multiple_vec(vec![public_key1, public_key2, public_key3]);

        assert_eq!(pk.h, BigInt::from(70));
        assert_eq!(pk.params, params);
    }

    #[test]
    fn combine_shares() {
        let share1 = BigInt::from(5);
        let share2 = BigInt::from(2);
        let product = ElGamal::combine_shares(
            &[&share1, &share2],
            &ElGamalParameters {
                p: BigInt::from(8),
                g: BigInt::from(5),
            },
        );

        assert_eq!(product, BigInt::from(2));
    }

    #[test]
    fn combine_shares_real_keys() {
        let share1 = BigInt::from_str_radix("44ee6e68d64cca6b341221450296c9872ae734da140f9b46800c46c1aa4a841b6c0d9f54521944a21f5307c46b0e614f32a2e013c958b5fdcb530ba577da8d238b9d353ce74544ad84a87d041efa24a43264d2e27d521038b9376f0df1dea892", 16).unwrap();
        let share2 = BigInt::from_str_radix("e5e24ba8aa2adb0c2959c3481e0cc668cd9bb612232cf0029f25ef6bdc4b3ea092a2443d552df1abfc04342681c47c6689346b9417626ab1bdcb8872efc1739b5fbbe5dab77a47b27f854577160a9ba82885c67ff911b20265ba42d8e086bf2a", 16).unwrap();
        let product = ElGamal::combine_shares(
            &[&share1, &share2],
            &ElGamalParameters {
                p: BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff", 16).unwrap(),
                g: BigInt::from(2),
            },
        );

        assert_eq!(product, BigInt::from_str_radix("623252d8e2ef242720c4e3455140b94cbc68ae44e1e1e1440d5d25fb30a1ae11edb251f25a18665b05853bc31a8b44699887355f3ac95d38697375237e9066fe0f7141246674116679866dbd0f407b107c16aacea29f267d203c0c5d30e97417", 16).unwrap());
    }

    #[test]
    fn encrypt_decrypt_distributed() {
        let message = BigInt::from(88);
        let params = ElGamalParameters {
            p: BigInt::from(2753),
            g: BigInt::from(1035),
        };

        let private_key1 = ElGamalPrivateKey::new(&BigInt::from(174), params.clone());
        let public_key1 = private_key1.extract_public_key();

        let private_key2 = ElGamalPrivateKey::new(&BigInt::from(45), params.clone());
        let public_key2 = private_key2.extract_public_key();

        let pk = ElGamalPublicKey {
            h: public_key1.h * public_key2.h % &params.p,
            params,
        };

        let c = ElGamal::encrypt(&message, &BigInt::from(3), &pk);

        let share1 = ElGamal::decrypt_share(&c, &private_key1);
        let share2 = ElGamal::decrypt_share(&c, &private_key2);

        assert_ne!(share1, message);
        assert_ne!(share2, message);

        let recovered_message = ElGamal::decrypt_shares(&c, &[&share1, &share2], &pk.params);
        assert_eq!(message, recovered_message)
    }

    #[test]
    fn encrypt_decrypt_additive_distributed() {
        let m1 = BigInt::from(88);
        let m2 = BigInt::from(12);
        let params = ElGamalParameters {
            p: BigInt::from(2753),
            g: BigInt::from(1035),
        };

        let private_key1 = ElGamalPrivateKey::new(&BigInt::from(174), params.clone());
        let public_key1 = private_key1.extract_public_key();

        let private_key2 = ElGamalPrivateKey::new(&BigInt::from(45), params.clone());
        let public_key2 = private_key2.extract_public_key();

        let pk = ElGamalPublicKey {
            h: public_key1.h * public_key2.h % &params.p,
            params: params.clone(),
        };

        let c1 = ElGamal::encrypt(&m1, &BigInt::from(3), &pk);
        let c2 = ElGamal::encrypt(&m2, &BigInt::from(7), &pk);
        let c = ElGamal::add(&c1, &c2, &params);

        let share1 = ElGamal::decrypt_share(&c, &private_key1);
        let share2 = ElGamal::decrypt_share(&c, &private_key2);

        assert_ne!(share1, m1);
        assert_ne!(share2, m1);
        assert_ne!(share1, m2);
        assert_ne!(share2, m2);

        let recovered_message = ElGamal::decrypt_shares(&c, &[&share1, &share2], &pk.params);
        assert_eq!(m1 + m2, recovered_message)
    }

    #[test]
    fn re_encryption_proof() {
        let message = BigInt::from(1);

        let params = ElGamalParameters {
            // 2048-bit size modulus
            p: BigInt::from_str_radix("F52E0A34AA46657BE51CE1BFEA30D0BE7FD65D879AB9B2CAD7CDFECE734F074065869ABFD3B9FF77C77ACCE7824F75BB51D8BC0A2D83974D3CFE14100375C9DE52C4C038FDD03B4BC30616EE1997E7D5AB108DA95BEC7B7D5394781B2CE85000D8A7A02306ED48F7242D0277A8EE0DF0ABAC3725A9349FA4F1883D89FD5A027D97670368369B266F4BCDD1D4F266303580003FC02B82B97B86674D7387083143583ACA5C5AA63A86D6C88CF95F203203DCFE726C0098790B2B64AE3DD58ACDFDB912A75688B593F9D1342D49408ACAE04B184DA61976FCBF87F0A608CBC7F7B152D57C0F2F1E090A55EFA74E49BDCABEEF9A59EC9BD3D89FC8BBD920D5CA1CED", 16).unwrap(),
            g: BigInt::from(1035),
        };

        let private_key = ElGamalPrivateKey::new(&BigInt::from(174), params.clone());
        let public_key = private_key.extract_public_key();

        let zeta = BigInt::from(13);

        let cipher = ElGamal::encrypt(&message, &BigInt::from(3), &public_key);
        let zero_encryption = ElGamal::encrypt(&BigInt::from(0), &zeta, &public_key);
        let cipher_plus_zero = ElGamal::add(&cipher, &zero_encryption, &params);

        let recovered_message = ElGamal::decrypt(&cipher_plus_zero, &private_key);
        let e_minus = ElGamal::sub(&cipher_plus_zero, &cipher, &params);
        assert_ne!(cipher, cipher_plus_zero);
        assert_eq!(recovered_message, message);
        assert_eq!(ElGamal::decrypt(&e_minus, &private_key), BigInt::from(0));

        // e' = E(0, alpha); alpha random
        let alpha = BigInt::from(3);
        let c2 = BigInt::from(23);
        let s2 = BigInt::from(57);
        let e_prime = ElGamal::encrypt(&BigInt::from(0), &alpha, &public_key);

        let zv_to_c2 = public_key.h.modpow(&c2, &params.p);
        let t2 = mod_div(&(params.g.modpow(&s2, &params.p)), &zv_to_c2, &params.p).unwrap();

        // Challenge c random
        let c = BigInt::from(137);

        // c1 = c − c2 (mod u)
        let c1 = (c.clone() - c2.clone()) % params.p.clone();
        // beta = c1 * zeta + alpha
        //let zeta = BigInt::from(347);
        let beta = (&c1 * zeta + &alpha) % &params.p;

        // Verification

        // c = c1 + c2 (mod u)
        let c_ = (c1.clone() + c2.clone()) % params.p.clone();
        assert_eq!(c, c_);

        // g^s2 =? Z^c2*t2
        let g_s2 = params.g.modpow(&s2, &params.p);
        let rhs = public_key.h.modpow(&c2, &params.p) * t2 % params.p.clone();
        assert_eq!(g_s2, rhs);

        // E(0,β)= c1 * e_minus + e_prime
        let beta_enc = ElGamal::encrypt(&BigInt::from(0), &beta, &public_key);

        let c1_e_minus = Cipher(
            e_minus.0.modpow(&c1, &params.p),
            e_minus.1.modpow(&c1, &params.p),
        );
        let beta_question_mark = ElGamal::add(&c1_e_minus, &e_prime, &params);

        assert_eq!(beta_enc, beta_question_mark);
    }

    #[test]
    fn test_bn() {
        let g = BigInt::from(2);
        let zeta = BigInt::from(3);
        let alpha = BigInt::from(5);
        let c1 = BigInt::from(2);

        let beta = &c1 * &zeta + &alpha;

        println!("{}", beta.to_str_radix(10));

        let modulus = BigInt::from(1024);
        let lhs = g.modpow(&beta, &modulus);

        println!("{}", lhs.to_str_radix(10));

        let rhs =
            g.modpow(&zeta, &modulus).modpow(&c1, &modulus) * g.modpow(&alpha, &modulus) % &modulus;
        println!("{}", rhs.to_str_radix(10));

        let rhs =
            g.modpow(&c1, &modulus).modpow(&zeta, &modulus) * g.modpow(&alpha, &modulus) % &modulus;
        println!("{}", rhs.to_str_radix(10));

        assert_eq!(lhs, rhs);
    }
}

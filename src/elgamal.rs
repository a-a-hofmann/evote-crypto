use alloc::vec::Vec;
use core::ops::{Div, Mul, Sub};

use num_bigint::BigInt;
use num_traits::Signed;
use rayon::prelude::*;

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
        assert!(public_key.params.belongs_to_group(nonce), "Nonce too big: {}", nonce.to_str_radix(16));

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

    pub fn decrypt_with_heuristic(cipher: &Cipher, private_key: &ElGamalPrivateKey, upper_bound: u64) -> BigInt {
        let Cipher(c, d) = cipher;

        let modulus = private_key.params.p.clone();
        let sk = private_key.x.clone();

        let generator = private_key.params.g.clone();
        let c_to_sk = c.modpow(&sk, &modulus);
        let g_to_m = math::mod_div(&d, &c_to_sk, &modulus).expect("Cannot find mod inverse");

        math::brute_force_dlog_with_heuristic(&g_to_m, &generator, &modulus, upper_bound)
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

        c = c % &params.p;
        d = d % &params.p;

        Cipher(c, d)
    }

    pub fn add_parallel(ciphers: Vec<Cipher>, params: &ElGamalParameters) -> Cipher {
        let c = BigInt::from(1);
        let d = BigInt::from(1);
        let c = Cipher(c, d);
        let sum: Cipher = ciphers
            .par_iter()
            .cloned()
            .reduce(|| c.clone(), |cipher1, cipher2| Cipher(&cipher1.0 * &cipher2.0 % &params.p, &cipher1.1 * &cipher2.1 % &params.p));

        sum
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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use indicatif::ProgressBar;
    use num_bigint::BigInt;
    use num_traits::Num;
    use rayon::prelude::*;

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

    #[test]
    fn test_many_votes() {
        use indicatif::ParallelProgressIterator;

        let x = BigInt::from_str_radix("c308aea0cd4859a06964f3aef8193705668887e889b259dcb3475cf793c3ede229ebef203716f56d5aa46f8ddf601da5d34468a1e006b61fd412d56dc41ef01e5144d150c62e3d51b6824ed7514d1a36bce7abbea0501a093f2348d6e6bdfebb0dcebc789ca352b9874fd1519deb85e13af2879394e5ac62e252cac530b6b98da77d7b64c56156ea77f22416815f44e90a879e020ed543f63c03323f2e42d3d14e1c01b7e0c1bad4e289f274ee73f253622c671c0a02688f3cf98607236a99d1f83bde87c4a53ed6910d21501c926d8e492406aa42ef6e0559dc49ca1cd41821f80bcea45d52306c4833a2fd0a73606b714b5d20c4fbaa43d1c94c09fa614a", 16).unwrap();
        let h = BigInt::from_str_radix("61cb62ec3387adbdf2f01c6169f6493f86890c6779f92f375426ea69c7f7e79baef2ad7319441342690e4dbb428634270a7081571717fc8d997f1c4c7c92f84566c53c123092e4ab1e9df18ddbb9e5f98ca386d8b19d6e65c116ad12bfa07506f57d1890d7a08f8fb1fc0f354d4f8cebee9fc81c06502c8fac80e67fa00fffe14ee3b311a81a20217809e56831a1050e3a61724ecf8682625452ebc290d1d4aca22c29380039e6181bc0e2df19b9a8f76bd6e3a0ea5e089b9182840b661efb9b1ce3ca3f39be2025dcbce2d3f2e56a97f637c79bca16da9e4edb6ebb02564794465cf15d09cdea5f24055016e8bf3d9652eea75df5a4d49e62819e7f2da70f6b", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters { p, g };
        let q = &params.q();
        let private_key = ElGamalPrivateKey { x, params: params.clone() };
        let public_key = ElGamalPublicKey { h, params: params.clone() };

        let n: u64 = 100000;
        let pb = ProgressBar::new(n);
        pb.set_draw_delta(n as u64 / 100); // redraw every 1% of additional progress

        let before = Instant::now();

        let nonces: Vec<BigInt> = vec![1; n as usize].par_iter().enumerate().map(|(index, _)| BigInt::from(index % q + 1)).collect();

        let vote = BigInt::from(1);
        let ciphertext = ElGamal::encrypt(&vote, &BigInt::from(3), &public_key);
        let mut ciphers: Vec<Cipher> = nonces.par_iter().progress_with(pb).map(|_| ciphertext.clone()).collect();
        ciphers[1] = ElGamal::encrypt(&BigInt::from(0), &BigInt::from(7), &public_key);

        println!("Computed ciphers: {}", ciphers.len());
        println!("Elapsed time: {:.2?}", before.elapsed());

        assert_eq!(ciphers.len(), n as usize);
        assert_eq!(ciphers[0], ciphertext);
        assert_eq!(ciphers[ciphers.len() - 1], ciphertext);

        println!("Compute sum");

        let before_sum = Instant::now();
        let sum = ElGamal::add_parallel(ciphers.clone(), &params);
        println!("Elapsed time sum: {:.2?}", before_sum.elapsed());

        let before_decrypt = Instant::now();
        let plaintext = ElGamal::decrypt_with_heuristic(&sum, &private_key, n);
        println!("Elapsed time decrypt: {:.2?}", before_decrypt.elapsed());
        assert_eq!(plaintext, BigInt::from(n - 1));

        println!("Total elapsed time: {:.2?}", before.elapsed());
    }
}

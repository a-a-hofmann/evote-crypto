use num_bigint::BigInt;

use crate::elgamal::{Cipher, ElGamal, ElGamalParameters, ElGamalPrivateKey, ElGamalPublicKey};
use crate::hash::hash_args;
use crate::math::mod_div;

/// Schnorr Proof - Key Generation
/// Proves knowledge of an ElGamal private key `x` that belongs to a public key `h`
pub struct SchnorrProof {
    pub challenge: BigInt,
    pub response: BigInt,
}

impl SchnorrProof {
    pub fn new(private_key: ElGamalPrivateKey, nonce: BigInt, unique_id: &BigInt) -> Self {
        let params = &private_key.params;
        let generator = &params.g;
        let modulus = &params.p;
        let q: BigInt = (modulus.clone() - 1) / 2;

        let public_key = private_key.extract_public_key();
        let sk = private_key.x.clone();

        assert!(nonce < q);
        let commitment: BigInt = generator.modpow(&nonce, &modulus);

        let hashed = hash_args(vec![&unique_id, &public_key.h, &commitment]);
        let challenge = hashed.0 % &q;

        let response = (nonce + (challenge.clone() * sk) % &q) % &q;

        SchnorrProof {
            challenge,
            response,
        }
    }

    pub fn verify(&self, public_key: &ElGamalPublicKey, unique_id: &BigInt) -> bool {
        let params = &public_key.params;
        let generator = &params.g;
        let modulus = &params.p;
        let q: BigInt = (modulus.clone() - 1) / 2;

        let g_to_d = generator.clone().modpow(&self.response, &modulus);
        let h_to_c = public_key.h.clone().modpow(&self.challenge, &modulus);
        let commitment = mod_div(&g_to_d, &h_to_c, &modulus).expect("Cannot compute mod_inverse");

        let challenge = hash_args(vec![&unique_id, &public_key.h, &commitment]).0 % &q;

        let lhs = generator.clone().modpow(&self.response, &modulus);
        let rhs = commitment * &public_key.h.modpow(&self.challenge, &modulus) % modulus;

        let first = challenge == self.challenge;
        let second = lhs == rhs;
        first && second
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RandomizedProofParameters {
    pub alpha: BigInt,
    pub c2: BigInt,
    pub s2: BigInt,
}

pub struct ReEncryptionProof {
    pub e_prime: Cipher,
    pub t2: BigInt,
    pub c1: BigInt,
    pub c2: BigInt,
    pub beta: BigInt,
    pub s2: BigInt,
}

impl ReEncryptionProof {
    pub fn new_interactive(
        zeta: &BigInt,
        randomized_params: &RandomizedProofParameters,
        challenge: &BigInt,
        public_key: &ElGamalPublicKey,
        voter_public_key: &ElGamalPublicKey,
    ) -> Self {
        let params = &public_key.params;

        let e_prime = ElGamal::encrypt(&BigInt::from(0), &randomized_params.alpha, &public_key);

        // Compute t2 = g^s2
        let zv_to_c2 = voter_public_key
            .h
            .clone()
            .modpow(&randomized_params.c2, &params.p);
        let t2 = mod_div(
            &(params.g.clone().modpow(&randomized_params.s2, &params.p)),
            &zv_to_c2,
            &params.p,
        )
        .unwrap();

        // c1 = c - c2 % mod p
        let c1 = (challenge - &randomized_params.c2) % &params.p;

        // beta = c1 * zeta + alpha
        let beta = (&c1 * zeta + &randomized_params.alpha) % &params.p;

        ReEncryptionProof {
            e_prime,
            t2,
            c1,
            c2: randomized_params.c2.clone(),
            beta,
            s2: randomized_params.s2.clone(),
        }
    }

    pub fn new_non_interactive(
        zeta: &BigInt,
        randomized_params: &RandomizedProofParameters,
        public_key: &ElGamalPublicKey,
        voter_public_key: &ElGamalPublicKey,
    ) -> Self {
        let params = &public_key.params;

        let e_prime = ElGamal::encrypt(&BigInt::from(0), &randomized_params.alpha, &public_key);

        // Compute t2 = g^s2
        let zv_to_c2 = voter_public_key
            .h
            .clone()
            .modpow(&randomized_params.c2, &params.p);
        let t2 = mod_div(
            &(params.g.clone().modpow(&randomized_params.s2, &params.p)),
            &zv_to_c2,
            &params.p,
        )
        .unwrap();

        let challenge = hash_args(vec![&e_prime.0, &e_prime.1, &t2]);

        // c1 = c - c2 % mod p
        let c1 = (challenge.0 - &randomized_params.c2) % &params.p;

        // beta = c1 * zeta + alpha
        let beta = (&c1 * zeta + &randomized_params.alpha) % &params.p;

        ReEncryptionProof {
            e_prime,
            t2,
            c1,
            c2: randomized_params.c2.clone(),
            beta,
            s2: randomized_params.s2.clone(),
        }
    }

    pub fn verify(
        &self,
        e_minus: &Cipher,
        challenge: &BigInt,
        public_key: &ElGamalPublicKey,
        voter_public_key: &ElGamalPublicKey,
    ) -> bool {
        let params = &public_key.params;
        let modulus = &params.p;

        // c = c1 + c2 % mod p
        let c1_plus_c2 = (&self.c1 + &self.c2) % modulus;
        assert_eq!(*challenge, c1_plus_c2);
        let first_condition = *challenge == c1_plus_c2;

        // E(0, beta) = c1 * e_minus + e_prime
        // lhs
        let beta_cipher = ElGamal::encrypt(&BigInt::from(0), &self.beta, &public_key);

        // rhs
        let c1_e_minus = Cipher(
            e_minus.0.modpow(&self.c1, modulus),
            e_minus.1.modpow(&self.c1, modulus),
        );
        let beta_rhs = ElGamal::add(&c1_e_minus, &self.e_prime, &params);

        // Proof of knowledge of the witness zeta
        assert_eq!(beta_cipher, beta_rhs);
        let second_condition = beta_cipher == beta_rhs;

        // Proof of knowledge of the voter's private key
        // g^s2 =? Z^c2*t2
        let g_s2 = params.g.modpow(&self.s2, modulus);
        let rhs = voter_public_key.h.clone().modpow(&self.c2, modulus) * self.t2.clone() % modulus;
        assert_eq!(g_s2, rhs);
        let third_condition = g_s2 == rhs;

        first_condition && (second_condition || third_condition)
    }

    pub fn verify_non_interactive(
        &self,
        e_minus: &Cipher,
        public_key: &ElGamalPublicKey,
        voter_public_key: &ElGamalPublicKey,
    ) -> bool {
        let params = &public_key.params;
        let modulus = &params.p;

        // E(0, beta) = c1 * e_minus + e_prime
        // lhs
        let beta_cipher = ElGamal::encrypt(&BigInt::from(0), &self.beta, &public_key);

        // rhs
        let c1_e_minus = Cipher(
            e_minus.0.modpow(&self.c1, modulus),
            e_minus.1.modpow(&self.c1, modulus),
        );
        let beta_rhs = ElGamal::add(&c1_e_minus, &self.e_prime, &params);

        // Proof of knowledge of the witness zeta
        assert_eq!(beta_cipher, beta_rhs);
        let second_condition = beta_cipher == beta_rhs;

        // Proof of knowledge of the voter's private key
        // g^s2 =? Z^c2*t2
        let g_s2 = params.g.modpow(&self.s2, modulus);
        let rhs = voter_public_key.h.clone().modpow(&self.c2, modulus) * self.t2.clone() % modulus;
        assert_eq!(g_s2, rhs);
        let third_condition = g_s2 == rhs;

        // c = c1 + c2 % mod p
        let c1_plus_c2 = (&self.c1 + &self.c2) % modulus;
        let e_prime = ElGamal::sub(&beta_cipher, &c1_e_minus, &public_key.params);
        let challenge = hash_args(vec![&e_prime.0, &e_prime.1, &self.t2]).0;
        assert_eq!(challenge, c1_plus_c2);
        let first_condition = challenge == c1_plus_c2;

        first_condition && (second_condition || third_condition)
    }
}

#[derive(Default, Debug)]
pub struct BallotProof {
    pub a0: BigInt,
    pub a1: BigInt,
    pub b0: BigInt,
    pub b1: BigInt,
    pub c0: BigInt,
    pub c1: BigInt,
    pub r0: BigInt,
    pub r1: BigInt,
}

impl BallotProof {
    pub fn verify(
        &self,
        cipher: &Cipher,
        public_key: &ElGamalPublicKey,
        unique_id: &BigInt,
    ) -> bool {
        let params = &public_key.params;
        let ElGamalParameters { p, g } = params;

        let lhs = g.modpow(&self.r0, &p);
        let rhs = &self.a0 * cipher.0.modpow(&self.c0, p) % p;
        let first_condition = lhs == rhs;
        assert!(first_condition, "1st condition failed");

        let lhs = g.modpow(&self.r1, p) % p;
        let rhs = &self.a1 * cipher.0.modpow(&self.c1, p) % p;
        let second_condition = lhs == rhs;
        assert!(second_condition, "2nd condition failed");

        let lhs = public_key.h.modpow(&self.r0, p);
        let rhs = &self.b0 * cipher.1.modpow(&self.c0, p) % p;
        let third_condition = lhs == rhs;
        assert!(third_condition, "3rd condition failed");

        let lhs = public_key.h.modpow(&self.r1, p);
        let d_div_g = mod_div(&cipher.1, g, p).expect("Unable to compute mod_div");
        let rhs = &self.b1 * d_div_g.modpow(&self.c1, p) % p;
        let fourth_condition = lhs == rhs;
        assert!(fourth_condition, "4th condition failed");

        let hashed = hash_args(vec![
            &public_key.h,
            unique_id,
            &cipher.0,
            &cipher.1,
            &self.a0,
            &self.b0,
            &self.a1,
            &self.b1,
        ]);
        let hash_size = BigInt::from(hashed.1 as u32);
        let rhs = hashed.0 % &hash_size;
        let lhs = (&self.c0 + &self.c1) % &hash_size;
        let fifth_condition = lhs == rhs;
        assert!(fifth_condition, "5th condition failed");

        first_condition
            && second_condition
            && third_condition
            && fourth_condition
            && fifth_condition
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Num;

    use crate::elgamal::ElGamalParameters;

    use super::*;

    fn create_crypto_material(
        sk: Option<BigInt>,
    ) -> (ElGamalPrivateKey, ElGamalPublicKey, ElGamalParameters) {
        let params = ElGamalParameters {
            // 2048-bit size modulus
            p: BigInt::from_str_radix("F52E0A34AA46657BE51CE1BFEA30D0BE7FD65D879AB9B2CAD7CDFECE734F074065869ABFD3B9FF77C77ACCE7824F75BB51D8BC0A2D83974D3CFE14100375C9DE52C4C038FDD03B4BC30616EE1997E7D5AB108DA95BEC7B7D5394781B2CE85000D8A7A02306ED48F7242D0277A8EE0DF0ABAC3725A9349FA4F1883D89FD5A027D97670368369B266F4BCDD1D4F266303580003FC02B82B97B86674D7387083143583ACA5C5AA63A86D6C88CF95F203203DCFE726C0098790B2B64AE3DD58ACDFDB912A75688B593F9D1342D49408ACAE04B184DA61976FCBF87F0A608CBC7F7B152D57C0F2F1E090A55EFA74E49BDCABEEF9A59EC9BD3D89FC8BBD920D5CA1CED", 16).unwrap(),
            g: BigInt::from(1035),
        };

        let x = sk.unwrap_or_else(|| BigInt::from(174));
        let private_key = ElGamalPrivateKey::new(&x, params.clone());
        let public_key = private_key.extract_public_key();

        (private_key, public_key, params)
    }

    #[test]
    fn generate_and_verify_proof() {
        assert_eq!(BigInt::from(4) % BigInt::from(3), BigInt::from(1));

        let (private_key, public_key, params) = create_crypto_material(None);
        let public_key2 = ElGamalPrivateKey::new(&BigInt::from(173), params).extract_public_key();

        let unique_id = BigInt::from(123456);

        let proof = SchnorrProof::new(private_key, BigInt::from(17), &unique_id);
        assert!(proof.verify(&public_key, &unique_id));
        assert!(!proof.verify(&public_key2, &unique_id));
        assert!(!proof.verify(&public_key, &(unique_id + BigInt::from(1))));
    }

    #[test]
    fn re_encryption_interactive_proof() {
        // Voter's choice
        let message = BigInt::from(1);

        // Setup
        let (_, public_key, params) = create_crypto_material(None);

        let (_, voter_public_key, _) = create_crypto_material(Option::from(BigInt::from(237)));

        // Zeta is the witness
        let zeta = BigInt::from(13);

        // Encrypt the voter's choice, create a random encryption of zero using the witness, and add it to the cipher
        let cipher = ElGamal::encrypt(&message, &BigInt::from(3), &public_key);
        let zero_encryption = ElGamal::encrypt(&BigInt::from(0), &zeta, &public_key);
        let cipher_plus_zero = ElGamal::add(&cipher, &zero_encryption, &params);

        // Create the random parameters used for the proof
        // Challenge c random
        let challenge = BigInt::from(137);
        let alpha = BigInt::from(3);
        let c2 = BigInt::from(23);
        let s2 = BigInt::from(57);
        let randomized_params = RandomizedProofParameters { alpha, c2, s2 };

        // Generate proof
        let proof = ReEncryptionProof::new_interactive(
            &zeta,
            &randomized_params,
            &challenge,
            &public_key,
            &voter_public_key,
        );

        // Verify: isolate the encryption of zero
        let e_minus = ElGamal::sub(&cipher_plus_zero, &cipher, &params);
        let verification = proof.verify(&e_minus, &challenge, &public_key, &voter_public_key);
        assert!(verification);
        assert_eq!(e_minus, zero_encryption);
    }

    #[test]
    fn re_encryption_non_interactive_proof() {
        // Voter's choice
        let message = BigInt::from(1);

        // Setup
        let (_, public_key, params) = create_crypto_material(None);

        let (_, voter_public_key, _) = create_crypto_material(Option::from(BigInt::from(237)));

        // Zeta is the witness
        let zeta = BigInt::from(13);

        // Encrypt the voter's choice, create a random encryption of zero using the witness, and add it to the cipher
        let cipher = ElGamal::encrypt(&message, &BigInt::from(3), &public_key);
        let zero_encryption = ElGamal::encrypt(&BigInt::from(0), &zeta, &public_key);
        let cipher_plus_zero = ElGamal::add(&cipher, &zero_encryption, &params);

        // Create the random parameters used for the proof
        // Challenge c random
        let alpha = BigInt::from(3);
        let c2 = BigInt::from(23);
        let s2 = BigInt::from(57);
        let randomized_params = RandomizedProofParameters { alpha, c2, s2 };

        // Generate proof
        let proof = ReEncryptionProof::new_non_interactive(
            &zeta,
            &randomized_params,
            &public_key,
            &voter_public_key,
        );

        // Verify: isolate the encryption of zero
        let e_minus = ElGamal::sub(&cipher_plus_zero, &cipher, &params);
        let verification = proof.verify_non_interactive(&e_minus, &public_key, &voter_public_key);
        assert!(verification);
        assert_eq!(e_minus, zero_encryption);
    }

    #[test]
    fn test_proof_generated_in_js_lib() {
        let params = ElGamalParameters {
            p: BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff", 16).unwrap(),
            g: BigInt::from_str_radix("2", 10).unwrap(),
        };
        let public_key = ElGamalPublicKey {
            h: BigInt::from_str_radix("761ac9c62d5bfcee1ce46cb95c318c439b4916b48627d6771c033eb000fa055c2df846f380ed7d782d8cff2e81d1c103fac759697ab5f329a474067e979cc1a1990890d0a567be2656aed51371b3c59787ac31808afa79327e01a068c0e5c7d6", 16).unwrap(),
            params: params.clone(),
        };
        let proof = SchnorrProof {
            challenge: BigInt::from_str_radix("93259cedf8d5dd6eff73b9fce9d4882255d010765ceae65446fad3e8d39976f472a048f779e92967cfc0d48d28aca6a52aeb23a51af2dec93773e6b01551c2df", 16).unwrap(),
            response: BigInt::from_str_radix("66e36e2e39d8041da87d304ad3da004b8225f974d540593444339693d83a039ec5d08bff9cc2e22fe9169af6b2a055927c097a89b0137301557565b5fb76313c0d48af6eefd6b3005b3a18b1520e78a898ab79acf35f6424b2f05947d16d8c07", 16).unwrap(),
        };

        let unique_id = BigInt::from_str_radix(
            "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48",
            16,
        )
        .unwrap();

        let verifies = proof.verify(&public_key, &unique_id);
        assert!(verifies);
    }

    #[test]
    fn test_ballot_proof_0_generated_in_js_lib() {
        let unique_id = BigInt::from_str_radix(
            "f6357c14c3d573f308c3b6cd028d284a7cc332ce96ab2c2836a56cb3a0f91600",
            16,
        )
        .unwrap();
        let encrypted0 = Cipher(
            BigInt::from_str_radix("35d829e6a73d25b97543c274db920aa35d19df7d46c6a5e8a71b20eed7e96999361ce14e9497b5142bea4f9ef311ae8da5a5e5f56d058010779805636e71b60af2aa8da1e516b238cfb0ceaa8aed238990e5def444658cbfcc2a660a0daed72f", 16).unwrap(),
            BigInt::from_str_radix("2054048385028a5fc06e1a13a9d65dbe65cc8d2923c12c530861d57d36af6c39830379cf5644b7674632cea381c898f1ceefb81f85acb799e548e5e0fbcdb3c0e54b7d69c2747cd46556d517d0569a7b266dc7287816637195d134d77af14ff5", 16).unwrap(),
        );

        let h = BigInt::from_str_radix("a412b1f2062eadf5049b0cfd765b3d2af9fc6fe9ba68e7e68f900f49799927425ab22fc138855f25f62ba992575d4c74b3964c18741195430eee52cfce21950db67598b4b17bc6bef9566259c71c26095027bf388d360bb1d432d31abdc99919", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters { p, g };
        let public_key = ElGamalPublicKey { h, params };

        // Proof of 0
        let a0: BigInt = BigInt::from_str_radix("72d7e19b3e4c57ab516d2556885e0866eab8dcc97ec7ff87b1ce5d028d37f7219e593af0a4401b6ff7b33eead9635dd6e63405112f15964b800f258098a46cb45b4fc1ec23941d0e836fc5cd3709228c35f5ee940ed6fdad7034ca22ad0b6d91", 16).unwrap();
        let a1: BigInt = BigInt::from_str_radix("ee3691c7502249275dfd2593851a5d8d889b27e491f92a90fd0a1b7f8990363e92917d12870db84a7c261ddae70718807838be268a67f8f16b8da8755f5e7d4f0f3c1c0f433698095ccd50a72d89b1481c202d13b3eddd5092077a2b13c31305", 16).unwrap();
        let b0: BigInt = BigInt::from_str_radix("5544102672b28a105219cd0774c8b3a46c930b200d4a6c9e9930f671c6979c446a8e4dd2e76984226ba516de06c885c12f1ad53e4d892be412a5e04a3f0f22847d858edb573c033bc143857f6de3e4b8fabd6e78f1cd09c0410419dbd904d7c2", 16).unwrap();
        let b1: BigInt = BigInt::from_str_radix("d4b03b54c14396908187df0ee9ac47659b56dffd405ad8b8ff009bb856ffb262e76fdce6ca0c51c4db0d5b24fb47c4150d84caa97f38b532c1e844785007ce66556f06ddbbeae2bd4958bfc38ec785b48925d8e36afb0a0e37d89e14659d0f30", 16).unwrap();
        let c0: BigInt = BigInt::from_str_radix("1a9", 16).unwrap();
        let c1: BigInt = BigInt::from_str_radix("6d172c6b418c7d208dd4a4e1657caa3a0f48ca4fa36fb4f24d9c2b33885463e8f320f9e827c7c07e2d9c3f1cbdaf306c410924194534f22074f7f4c2da87dec8fd3aa295684ffa22c7218ae62a2506bcf14fe3ba8d50e717782dd20f40ede5", 16).unwrap();
        let r0: BigInt = BigInt::from_str_radix("4559d3b92bf0bee1a7ca72038ff8ea9c953668c504ce595f63534d9f622cace1ebbf52bd3fa65f5a1ac105893765edc85521c3e46be27ae667ee6c3904f53fe2c9f288d1021541e595563b04f6a2c315310019c02a469967e14f1661da4fd94a", 16).unwrap();
        let r1: BigInt = BigInt::from_str_radix("36aa4723968eb9be7b6888b0ebf86850ffc0d40829aacd142f3192499f9fff02537cfe97b5c333f30857890170431e3e6e5de33b68ece8499c83b778b3763ff73ca5275294266f4ecd3dfbdbcf9d8134286e7d0099fe0c49203540d0eea0fc", 16).unwrap();

        let proof = BallotProof {
            a0,
            a1,
            b0,
            b1,
            c0,
            c1,
            r0,
            r1,
        };

        let verifies = proof.verify(&encrypted0, &public_key, &unique_id);
        assert!(verifies);
    }

    #[test]
    fn test_ballot_proof_1_generated_in_js_lib() {
        let unique_id = BigInt::from_str_radix(
            "f6357c14c3d573f308c3b6cd028d284a7cc332ce96ab2c2836a56cb3a0f91600",
            16,
        )
        .unwrap();

        let h = BigInt::from_str_radix("4e26ca22986f59a6d2161ca69d377609db78bb89eb3c485c34d6ed8eec073ad726aab29727c6a84eb3e2bcd9c1f982e25db989465e8b834fb5abefc9ef31a019e6622db5a5ffd5910f963c3e9c6b144a75f9eb27c42f9e9f518de045ef34f654", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters { p, g };
        let public_key = ElGamalPublicKey { h, params };

        let encrypted1 = Cipher(
            BigInt::from_str_radix("8e0a454d56736a385e1e720c735dbad9c24dd6e8bc946e1f2f321067d1654e91fb3b5ca0b19d36221399975213917f28386830bfbff20eac0639bd499106b625b0e662ad041156dddd804219beb55b5f6a1d90811c6a8abf9fb6afacec983819", 16).unwrap(),
            BigInt::from_str_radix("52e55ee668d49a000d1426f78b89f0af7102cfc803048885a4a2c3263f72299bcbb6019b22af3440cfe5b931bc0782e115930a5c2dbf50400626591d911fd946f187cbb9ebea272f95e0b2b1e65416919850637ced3324662fc00c14774cb36e", 16).unwrap(),
        );

        let a0: BigInt = BigInt::from_str_radix("6f6b52b9575a33033894f6807ef3c33caf3cbe916db127babc1d315e308925a276832a2281f237664623b2b011efebf93772fe1ad459c3cd9790781ba23d82723ee1a854576f77a7fe0043be547243e5961dced3e178ac18d8e07b0d73089bb3", 16).unwrap();
        let a1: BigInt = BigInt::from_str_radix("5a89b277b7d15f266572a6e20327ed8de2fb33a8fcbcb419ce6916c397ff2457d2b5651bb6a6a5aa8cfde119ca73f6da90ba858e9b77a0581066e8953141f15a72460a91f871e18a5136b27a9095f57de77cbf3b11ad9bfcbc83d79c6c6b1f83", 16).unwrap();
        let b0: BigInt = BigInt::from_str_radix("85eafddf8da0cbf7f9e9b88a8dd4058c185400e8b5dfa9f28b5ee7db568b5f08d0ab0623a77bcf0b9590e52e431563205b84b7a2c3d4bd66e115c7aec974bf10954c116c592bca1f94a06ebb78d3ddd68ea33df345acfcb88e9f4759d6d66879", 16).unwrap();
        let b1: BigInt = BigInt::from_str_radix("d4f200a0037054a7faf2b799dade67a9ae7feef27dfb8dcfb788b934f067fd4904661ca08cdcd33faad62c20a1c4e89fb28747cf6a7fcd0e9838e2d46659322ddefa9af5d273bb424294b3bd45a7e0b03b197fab97882fda39adcedfb0a3570c", 16).unwrap();
        let c0: BigInt = BigInt::from_str_radix("ddb4cc4dece00f2510adb64816f1c31c2460c0f824980bcf25c91ecf9f635c4a1a3402518c083571c627116c7b52043a71f6a9f1953bad2183fe9e829c32491ec65720f164256a543e27e1dd8e05011ca2e73c340f00ef876d0c55e11b86bc", 16).unwrap();
        let c1: BigInt = BigInt::from_str_radix("122", 16).unwrap();
        let r0: BigInt = BigInt::from_str_radix("7ba056f0e15b39bf36cf06b34f63c3847b400c827862b0190284e131bb79dd0966f58d4e62d1006cbedc39737c77ad5b27aebcf55ec477c875c95e50085e85418561e5b51eaa5c22da521ec6d90006d169130383606f652c67567502afeb", 16).unwrap();
        let r1: BigInt = BigInt::from_str_radix("300b03603e935e8b52b65e771577671f96f19de58283bd127ac4b52cb23cc8cb3bab754a5e38afaddfa13454d7f0fae0ca52546a26f64b9b5a9fc8b835c265e4e0637d94af534e9370aee05f03c7eedc9f396086eceb3097f5c6cf6eb08de034", 16).unwrap();

        let proof = BallotProof {
            a0,
            a1,
            b0,
            b1,
            c0,
            c1,
            r0,
            r1,
        };

        let verifies = proof.verify(&encrypted1, &public_key, &unique_id);
        assert!(verifies);
    }

    #[test]
    fn test_ballot_proof_1_modp14_generated_in_js_lib() {
        let unique_id = BigInt::from_str_radix(
            "f6357c14c3d573f308c3b6cd028d284a7cc332ce96ab2c2836a56cb3a0f91600",
            16,
        )
        .unwrap();

        let h = BigInt::from_str_radix("6719296bcbb4d866bb644d80f44b522b5ef782f9276bc39beb929852fdb02dd6b517f1f0a03a189269654b5bda33dba81cb3830dac152dc9e15e72bbc6427b869d2775de321155671a5a553b1fe80f4276f0f4f0ce42073ab28f78e6c579b2c34bd6f55ee7d21ad5138284dc84db79fca9c2da817f195db4b3bef14e0e2786478fe4e4a40a001aee49c7a9e1bef202e0c142c2c741d13a05969d66cba166e4dbf35521841415ec104246c65606fcccc86652bf5cdbbd79015f8fcf15589c90a52f8ed554fdde305e475f4c4b4f3c0ebde0d2bfabd2c75925b46a25398b94edb9ca0510133fdc7cf517da1a9871ab86b39e135e84bb46964473955a8f407accd8", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters { p, g };
        let public_key = ElGamalPublicKey { h, params };

        let encrypted1 = Cipher(
            BigInt::from_str_radix("11bc579a04be3d23e391e17b1b34c85fab65b101970a1678ca3a52a4c02b301cc60f2eec236c2fd715763eb0b61c363163c596c5fb5d06e2ba56f8bbe3e5d41686e792c38ea9defe2adbebbfacd4baa35da2d3eaa5b2286c406819980b06c17a262f66dcdee11bded598562437c8dda49783778fea9e31ce82db5ac5b8153aa0b61220e52711074b2802f499b85f224410e5e08c756c0a5c342604c83ccc3269d495cd8034ea997343b3d0ac33ba10c7e7bbf7e18983d4a1e8c56dd1beb68086c0a45f455fe92da36446f6b2b0eea176e289b99cdc29552835eb0c3d76b722afbc2027fa2f93f2ebf9791d576479a1c6d8830f76dff302879ee0d43b180e16e5", 16).unwrap(),
            BigInt::from_str_radix("41fec2033a31c0e2a3250ce2ea5abc0ba2a5be0d5b5fcaa23fd0d023a53bc6ef2363e171b20201e9eca8bdbe678f1ff56a0096848e03b7fed27507d3aa563bba5ef491975376ce0c582f5de41707890ffe7f180acd0415d7575b28ff7c0620af99148c3fc58497664eaa1a9e32690e7d7b7b296faf25a311884545f88e915f57cf025d43f9e887868e6b32e8b9f57b74391bc05ef9229e78e2c1e4cf0674cd386739202f93b7e317639274128400db86f1419afe696fcf335acf342f2a7a1ca03b5f755393e82d7547315e4c83e65c66073ecdf7a258d81ac7a0242eb9297f598f9dbb8f61c571f72d519f8d274156514d0d68df33def400bf2247b387359217", 16).unwrap(),
        );

        let a0: BigInt = BigInt::from_str_radix("90a3dfac221f385f5329b19af2d85907648e3f7483a216f3e890b527b58b9c92d9ab76003fb69df6a4f03b655063e09c5eff7ae1e32683aebc7b303b1009b920000120faf715a95dae963158b41a41ee3f218d66332b5143e602b007e528bf5e28d3d4dd117aeb5003bddfb178047d48d1b6de921dd6a146b7aba75137ca706fed456ea593a1c84e0a029985ad56d17bd77ec8a0e796d3888802d7c69cc1c7113fb432c443037193e068dd8846781da52d9ff3760356a51a8c9a32e1b1a45ec061644908b0a42e402a79b935ecd034880663e81dc792eeb9d17adcf6f2c8a00a8c7835282d8cf811da8e73a8950849345daa151413e7797f11de28cfb6615083", 16).unwrap();
        let a1: BigInt = BigInt::from_str_radix("6d47ba1b852196908e8a1fca8332336e0974c446ba6d5be223da01f6fca8ee3d933e51b64399dd77306a9ab4a416a5efeeaed8635047d9128b1c411620836873911cacd46733e0c8f9c07ee04c47f34b1ce92bc7a035705f6a019370377abe661ca25c5b4ab3227e40b056045ffbe2422b342858fcf036c88682177c2c1fc80552ca21248600b4d2fc9f69c6b3ec3303fd681bc6fed8a68da9226cb9ed8b97d5c29a206d841edbf921eb861daad5680e62119a9e7caa2fa01191b22859b39c0a57acd69d013bb5c9cd12d47ca4654ee65e3c6afdcb7d7a947640570b2c99aa34c302d540984a124900d3ceadf8a140dc352fec5c0b6de2ceda9ea2760754ec56", 16).unwrap();
        let b0: BigInt = BigInt::from_str_radix("c136353a0ab188495cc6f8256ebb96a7db985d1a9fba58d547156b3df3e3ae4518bdb1071cdd2e58d222bf9758198a34aeb9265f642bc7d681d34e7df846b7f876111f1cc8e047ab74d71bc76da4961cb3c0cab6c3708f4c1b3fc0a5a27327fdd4496e4d45a2954f3855c59d6275a3bebe1b0d3c88c3ea0bb014c9c3d0c1561fe57e2d53b815965bcbe4abbda4ee2c8f475755678d0b542eb6657df9d15a186f1b7cc9dd21554de1bec37456c2a0da84847238fa5770260773c61f33b8834919d8572d8530144dac1cc912d961065762ebbeb0050230012c84f8d03dd2ffc10b1b4d970d38bbc6c224ee41d3db4ada179cf60a87e25ba33d1129cf7d97032603", 16).unwrap();
        let b1: BigInt = BigInt::from_str_radix("259a3b175b12f9cfc1fe7f8b125bb142bfc56d7dd2357138e9f2d1e87cab1ca2624ce2f7996196812d2d29c3f073b14d031331b43c97279fced70c76c0deeba079c1ce8004de81b3e8aef549015cc56a700929304498aa1b4a3579b52582a9a62daf1726d4b5d80bd44928330cfd43912a3bd608d44ab388872e847e52a4fc990ac28e574b8d8cbc0d7926fe698212ca3b86b403eaa41e13df21a248b94f7434e239fbde7d9e9af9d4eb82d38513fcdde79f991aa066d247c42caedc6dda351dfee99b4955828a83dd0790bdff0004dce68100472b4d10509f574b39a9036415836d247f4139ead8c35e252a40b43fcf341a23a9386ede03e4cf62641990cbe", 16).unwrap();
        let c0: BigInt = BigInt::from_str_radix("32", 16).unwrap();
        let c1: BigInt = BigInt::from_str_radix("153", 16).unwrap();
        let r0: BigInt = BigInt::from_str_radix("9544d6adb2ea0474398e4923ca464006d702ed9f3c361a410e8e55ef236232ca55d24382f96a18c7aa472d1ddf9e106abcaf71c46110416a3f336682f3ba5550dbb980c5e24b3a8fb8008e17e667374556be65205100651abf71249b383981e349ebe5ae316c4afdb79d9a2ad83b470bcfec1819e87dbd5e7e1ca0a9c68d3e12fe1e765f235794420b6e33c4f00abc426402f858f716dd64b5e6026a3e8ecf75d2f733015239f98da2e404bea49ff68aca3bb6c39faf302dbaf54a64a4ce05eb127401cbd9677ccb6981e28ceb0ad82e934ec3e23579b95daf63552a8223191e5902977c90c834c31eeec99ead1935518dede6422a721b190db42be3d4cfe8", 16).unwrap();
        let r1: BigInt = BigInt::from_str_radix("4df311562304f2ac797d7921f6e15c1abfb20856a77ee3e09909515168dcddf22bf0ebd1653ad415bc4311f003fc6158c072231a392c1a7d25ec22c59d34e052427c4be8681a7d3c6e8920c0930005c0983202b07835f621ba4b7ab13b7aa3ff71749b4d5685ce490fc594d997ea0b705225831b45ff06b76fa1f180c997b0192b0b8efc27f31739661bfdac4719e8ec8fe3167ee99330fc8d03c073912735c075a9bc6ad0386a4ea9ac84fe7ae7fc130555c9e4b1a47ecb875ee1612011c4dae02c29af184d6f730912f60e0f25d6d36754099eb19445f251a789ed760614f916ccacc6e0f74ad7b9f37823d4a1764f682f779a4593300167f06851a0a6e099", 16).unwrap();

        let proof = BallotProof {
            a0,
            a1,
            b0,
            b1,
            c0,
            c1,
            r0,
            r1,
        };

        let verifies = proof.verify(&encrypted1, &public_key, &unique_id);
        assert!(verifies);
    }
}

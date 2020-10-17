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
        let hash_size = &hashed.1;
        let rhs = hashed.0 % BigInt::from(*hash_size as u32);
        let lhs = (&self.c0 + &self.c1) % &hashed.1;
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
        let unique_id = BigInt::from(123456);
        let encrypted0 = Cipher(
            BigInt::from_str_radix("410f54603dc001a046697939d3e3a9db160f05028b9aee960b5a87e717c2b36ac268bba358cc82a5f34b036f0b34524c4c455337360911517276c92bc7201662c74e8464d705a0d5bf94fd75fc5879a1cf0c4fdbde455ea7d2d02e6ad1ab8b4c58444d0f421bc707847057040f8a336e64ddebf990a0e49dc8cdfaf2f5961b76a1c706c67c57a39355473a7ab81a952afc76e4edb3275579ed1eabcf96311b0646f8641fecd414dfb741038e5cf748bc1907f0948bd3c17096e7b7fa321c84e1046ab9d088dec44fc69f54181e269e3b7b6f3232435837cf6760acd6af7a58b4acb2ae19b69ad287d218fcbb59dee3653f5b9a3fcc133862a1b107cfc6543884", 16).unwrap(),
            BigInt::from_str_radix("b5eb4638b10dab051d9fb45d474c753880cd62a61a4f1b4c98c79a710f4c996412c2d09eb8d1fbd8cd7067a3fca9d53cdb64d06bbe8162fa41c03366a914be9718ef5a79d57b0af16b815709af28f21d14beb8bf76eb3b08607c952c969736e47d6ddcc2789cef3a84a0f705d20d5c0f62055b4bc82d734fcefa9c2ce40f2114120e07e868a89b43b0cec54a40ebba1fed7bff0d1be25e172df3e944f5091ea92742456ce4cb589f47ad20de9cf976e2a09d42f2201293b53d212eb79ff83e4548a7ceba375a442485dbb1b2ad0e06110b8a569ff6e339a3150fb0c776b0302cc12866a40109dbf21e8ce6a6da80634733fe892dbca5e38b8cea6f5b1af71166", 16).unwrap(),
        );

        let h = BigInt::from_str_radix("e450fde21b1a160dee9f1576f0771785182579b7f49777bcd6950acc3e06fe10330a5eb4f18f29c95076d81d83748ec19b4e7391f240765d268d601abb89ba7a69a5341a2a77bb356fbdfefb495f2820b5d213217e8db987f7ebc212b8c057702dac3cd293354ec238c5e3f55bced02bfd700efd78ca3ab128c863ae76c8e9a646ce844b0502994d3c2dd2d251c839a7570b7f36daab13fcad4ddc09d95cda51381b4f84248d7e24b6caec06664afa82b682fe1295a67ebac76dc8ea25f33836b64e9a09359f456da262bdafef43fb439224888710952bb312c1dbd3b2ff9a9b5ba8765a2a761171025f004c1a0b50dbbf7d6aab001632e4f526d1a1488964c6", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters { p, g };
        let public_key = ElGamalPublicKey { h, params };

        // Proof of 0
        let a0: BigInt = BigInt::from_str_radix("cf71b904ba78e01c0b3ed890bb9345d3070977dcb02f9a2f3b962f2c8d4e3305b9120c555fd55628b4f752462d5ff085285acc2b939bf87e6cef55fb1b562b49ccca14c286557a8543843e1109e347697df79ec8fbec1aaeb7ab6fab5cb5b9fe8b3ac7ee077299002aea25b8a91a73d6e48157b0f23b61b736e8015c4fd1e2f8e57002c65c10514d7dab11fb11b1704c1576f0c24d67dc53f93376881a9094c956087f045fb3b1120077df8509391a1535f2e52224a484645419d97af0dbf8c9eea53f6398a97a5bc49a8483a0a91b398b82cbd0cfcb93bfaf32a153419a3173d80e01bbe74b64a05b366ce2597f34d206ebcbe45feb5cd5675410d26ac210ca", 16).unwrap();
        let a1: BigInt = BigInt::from_str_radix("173ef4f724637a84eaa8fee66efdf386769753ea0f8f4f9314a01e6c6ea434b6ec9be394c6bb8eadc095142c3f37dcbfbd9597679a34b334edc7649ca7c0614ab39d88004c85a3c1ade421f551ef684b7affb7416dc9e840c5d20ba8e773c1dbfe4485d639807478562d2144d77a7c8b570f3eeb699f32d5900a0cbb28e06231bb7e01d87a79cb8eb095aa6a556271ef56e2b2fd1f1aa28a6a131c784ecf6ca21c511c36183ab63b3d902652ac0777630e9014533a883ba0e52d1d0143000f425bd885ed041514c4738dbe04a78d21883effb5c2c7cc68167e031db823deec3178d1a1f63bec240e1d68f02e07eeac841fb127c54975c33722bbc6dfe26df914", 16).unwrap();
        let b0: BigInt = BigInt::from_str_radix("984b4e5040b2aa22779b58b935042328ab09e516c5a35931ee3b21a9f00d4baeca08ec8ae1f4762d74bcc484fb71e1cb958a3333f9cc9758aab5eaabaa97bd77a2ca70e5b9f4a78c6b3f186152d0a19acf61e9984628504d1e83877169f4a552d024d1c9c1cb27a40787b99564ceebf8f73c04f9a89dda5fc140311a949a0d0292f6df785e0b03d5098b7104fe2c46a1682f567f9ad671e6f574e0e83cb088bf3b5d0a60deb05c15f5a6eb5d0b01a35994e7d439fc8479a9d6dabdc28da5066ec25cd2f4f26327453778a6e02bf622ea38ab48ade717f28b2282b24f73f353300ea721c9345e90aae28114bdf669c95ed6b542568a51381097c778e1aeb75e5", 16).unwrap();
        let b1: BigInt = BigInt::from_str_radix("e65a12b050e2ca2fd54718862cbefc6009d65183e2987e9872626d4f0e8ec3eb99bdb0d59075b2e84fd661c35b0bedf4216ad570d33ffea5d15cddbf44cbb4c7b91f3fb46d064a157939c74a59279e8f0825fcae1391bc281e27a2640cfd537f981553e18943c4207c6769918b3d477395c5491a526aee0d7251a0525c120013fc6c8c6ca5b36f9cde29738352ea2380f83b29e0387b73173681732964cd0ee6931ff5898f249364ebfc256d3dbb949cd2a4e3931ffc4162f51728bea2f0c52ed6b290191f355ab71e4d9714abad54b03322da95939a284be0f02b9259e385cae1294b4061ad91286db9b3201d98472fe83f958395a30af8165ee4c394986653", 16).unwrap();
        let c0: BigInt = BigInt::from_str_radix("7f5424f20c35f22ff9cab64b040f6db6b85f6cf88772f73108233ee0732eda9fb5737fc66a88bf1a5bcaf6a4491f086781eb2105e9f1fc46954671379d8c4d1fa378d46ab9e2650be115cb438cc547a5cef24c75afbd93fdd2eb459d0665218669bda4390dc70dfa9cbe8142688186f6ed579383297277723b65e0e34f8da95e077bb930c95ef78297a7124046695becea102a6fc0ea0aab1c5048fc0880b75802e45e293ffb1ad1708b2b649816b0e492c303ccf781f404125532b52b51230fd4b9344d6ca86e969eecf44f2b4843c80e965d3361bb110695796988494d3b90ba36807813494629310aa9fdf25a047496808763e2099b291a0ccd882a3451fc", 16).unwrap();
        let c1: BigInt = BigInt::from_str_radix("abdb0df3ca0dcfeabd37060ca4f363aa03c44d38fb17378c5de823d2050b9a4b925f8cb3010e76ccda0d987dfafa0775df6bd3fcab254702cf13ff5ba33cfc0477c64bfcc67c17112d0f77a469f7bdab33d4ff235e62b7b31468be739e3a708d5e91c49f7dc1d83a9110c655a408fc373c9fa5ccffb62ca59a5d7901243624c4f16aea44cbf24a9ce40d9438290bc2d7a284222d67cc1ff1e130af07c1f205cc86365a7850306542faef428d479b1de5f732376d8a1cba06f2fc6debca440e42c1650b2e833a480d8cd20d79f8ac4364e7d551717a0e2acb859eadc0b69bcbec5935f8aa8139d40a25d9ccd9f8f0bba8c9305501a5d63e07495c97d89e9e11", 16).unwrap();
        let r0: BigInt = BigInt::from_str_radix("8060bab43d2c125a1e9b6cae2588e46c87651ee386380f096f285aebef8a738b9e28427be905efb7b764eb8fdc2f302489b2af8ef4bbe93ba1a0ef29282953d62998f6bee9c96bc04c94fc236cd8a02bb26b01b82c6b0871709b686539bf5f76cbe858ae51a1ccfb11c03533aa645104a6be38e1090727b332a246ecd02e8f3f911ab2c6382b5248d1d88a2eaebf8b6394c2f7c9a5a408f5c97a2254c3a01a983d94a40c10dd8fa81d68bc4276be234e1f1394286dbc921a94fbe1f6808b6c98cba8f52cb35238117d01a333e8cff51188a1534aa9874e39f8ec7a75532f24551914a3e732f34c6eaddb23ce1252b77112d3fbae1ec115a01612ea559b8c0af1", 16).unwrap();
        let r1: BigInt = BigInt::from_str_radix("bfa7c0907425ced996271a9aceb98b1451ff6454ae7f7d3d5202399cdd7a551b7c4797273734b8f1de8bc0230accf5763c403db065eb1bf0c3987e58b9a4ffd41adb58c10a5b78362c0199dfb4a0ec1c768c8aaff4e05ac48d55e199b88ed9a14a64b34367ab16ddd5bb1b2f3b8f5df5def2c975b60c59af30372c6549fd6841966ee86ade0abde4a5947bb062c24ecbacfcf2ae9f39a02eb1c36c3ab6a263a96dc7cfc968ecbd1c1476286f11dbbe46676906cac530be165264b80b8938f55dc586fabfeb11afd6228bc3b39bcf00ab2283c8f3bdee9a7ac011b8bbe08b293a2614a3b65ae8e10c52ff53e9379e3708a5e32c3db6e79ea4314115eaf9d12f", 16).unwrap();

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
        let unique_id = BigInt::from(123456);

        let h = BigInt::from_str_radix("2cb82edb0e47fa46162702ceccb235b2002e60a96e5f620f839fad10e0b372c8837a24f8bfc2deef1907822921a03755737d8b39591631eb061e4d7e57cce13ee7b03537caa5f879397317038e0daefbb1f4f9fbfe7b646743cb6d16209099e89b4b221c9e64b1d1d972de44de6a7d71b99c4d644842e143be6a93d22d07a59e339e3afd8500597889bbf82f8a11acb2b94f48e5060faaaf608cc3f890a4fad420807852156bd812f187912529c64c57aef97d16ad8e12ec575d15de7ea09e7e455bd342aa8b3fb310cff0740102742a46aa471f24b47c002abe77cb8e905f760db8cb4e8d4ea53124bef3ee62a6ddb962a48a5209d124412ba022ea4b6e82a2", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters { p, g };
        let public_key = ElGamalPublicKey { h, params };

        let encrypted1 = Cipher(
            BigInt::from_str_radix("27e9caa99a8f2ebcf1ae3d6301ef9896559f22bcc55dd16a4f96a4879657ab297f4ece5667e4c605c1370f5f227196c22f94f3d1aa600c4f36bde57669b2cfcc3b28541bdba4b7becf46b89d26d1685b940d2ebb31c4dd144b94b3dede072613cf20a569adaa5c6a5c9e06a673a13b4d3fd081533f029453efd0fdc622b2a2128705c79ae90c81bd5cc53f50861b487bd14a85db7808b9dcbd1cac5d3c385a66a58044e821b70fd9e5cbf54689405ab71f667fc70a45d793e68e290717dff72ba67d03a1debee82e5b5828a56cea59db0eb2c6abaacadffb6573e106a5bdd429f23495ec8d9bf7a67b0f7dd93fa6a4ec749a6f9bbabe3235b5d4c5b423a8cc6a", 16).unwrap(),
            BigInt::from_str_radix("f7dd30df9d8c9236431e9d0b6e95c58958052ba973e70f0ffb107df6996d5894187e7c493d0c775addf8795fe6b69117fab333b870d092afc13f98cb56b35241610b0536f1b9c6ab0fa36a3e8a2b778ff37c7cce77a2fbba8049f8b0f220c429f7f9d09ad211013b595a5d8f4c7f20905e71d6de3cfa8e2a792a55115637c7a78c8db249210d876aed5dc7dfb1c91bac6f5ccc160d777c24948a7d3c3e069b9ab1e4fe7a8de46e10b13dcf992941be00ba4806ef20449f4ea783aaf9280568a7ffad31263041c5fadc3957a2933665b5d72dff794855f6a5e08f541583d471346db2bba135ebc7000a086360141d0be1b2ffb7b92bb449b9c6cc53dab6413fd8", 16).unwrap(),
        );

        let a0: BigInt = BigInt::from_str_radix("24ddf9c7d0e28e3112e245d341468c70924b48829019107cfcfb216a20d26d82339d1e7407f46812c7e73b7b68145fcd9f07b6642d1852c3851e040ff21d4f51030aba90a97343cc45e19834dbee6719f386a5e8a7c7da8ba6e8b49a4f7e04659393d28d31b6ae579325b443d4f5f1c166512ebb5f19ae6611f5d1fe3fa20682c9f3ee332386b50da7afe6262a31efaf821ef8c88687766ff132f5f5332fb4c82d3f54d1f8d22c059dbf5a1c9a7ffb35469e974543f01a8d28e09fc925937ba8241ffe62b3b15bec420d38cd98495ee187b4a1def957f919a764417287d734dd64a9f507824d2db475fb446792569db8ebb3b1422f0bc00fed9cdd5626605df8", 16).unwrap();
        let a1: BigInt = BigInt::from_str_radix("fcb2c71f00358174a8f1c8246a41dbcfc9290cc03cb52b83f33fd5ab2aa2425ab4bdf7537938eeb4c5366d7563e8182ed7e8f9373b8e1d229f1beb6f56f602a50a954e12008d46f35349cfcd7dbce19bc7021038fd15291081a31b5f463753057e36a70a35c32277f38f6ad5f0a157cfd287276b0a8c01b1e81230b44c321e1db38f211c665967b03498ff334e35b20732af797e461a521b6e08521311d484d5190cbe91cd5319dc6f047f2cbc8d402c813655d6d2d76a26490e3cb3cc14618cc400c92ef1ddef7ff6f11096a55f39d653e74ad03542acc168f56fbb9fb6c9fdacd2fb06209545d644271861dd9479ac9d5e28f0b6218e2090fdaad93b1a3666", 16).unwrap();
        let b0: BigInt = BigInt::from_str_radix("bf0fde2361aff43ad0c2baa25e5de048b64ba115824579d54bd802f66cb5ecf52515982bb18580ca99150b7fbbd3fcdb1a810c5160d59249e1643cdf892c0233ff28429994971e07cd57f45499d72da0039668c05048e8a42f9385b5e288d88a7e3bb38f324bc4a5d4b8467430c3dca4f815acad2d1a79754d17b83709d9c56e7fe6abd21f9b466adc7c74d5e85a6796b2e2fa66b18277f7d935d48d3909a787994e32253b9a3b686090507f104af6a70b5a0299e3288b55b8542d476119770289fc45ee45e8e034b5c91297bb176269188be12af2f43c7cc69c8940a34e77690a10e0a2702b39920029abc453a153a77a094c450bca2f3f59d422f90c7b0069", 16).unwrap();
        let b1: BigInt = BigInt::from_str_radix("2d6050c183aa2f4b01d176553f32f8343605ea6eab0a74e1db8c47f44355edf363c91dd8782205483b794a9c689c08eba751a424316d14af5cf2de81fd9c838e1782fb8e5d4daa7e798ac03f02dc54095ceec8aa3c1638ba616435978d5dbea5899b32314d404e8a79e26fcd3365a0fc9c296972afd4cc99452f7b1281aabfbb097bd3d655c312fb40fbcfc05d9de4447925b5747e19fb060d3f064e3c6d68d1a42b7a164ed39065ab5948c64040790ca46417418858ba6578736ea07e74f2bc193a0cc854958daa2274637d9c9d70ebd299c52b65d82a550c78af58a836c5b257fbad11fb889f028e4abccc5315b79c10f5cfef7eb03d40129ddce49e2e710f", 16).unwrap();
        let c0: BigInt = BigInt::from_str_radix("fac8c0af317a7e41d92d5065ca2e681e5db25f26c651e3e658bb6ce6f865826e3771de2f1becf1b22434d980ccb3cceab9d78e539d01995226d2945334042fc8f86ad17d4713fcb7c7f5ce1bdb625638bbaea99b8e0ff0de53aab03e9e04b2cd3edbe9ad286437ef64f8b7fb2fed9eaaf661cd29ec6d449c1852b0a7aa2c56d1ee382882838a9efbc312b1944f580668ff919052ef1e51ff0b2025d2e30e745f47ac3e33be9de44ad764545023f4bc746d1c3f6aead8d7672833aa8bd41b99a7940a60c0b2e4088526c27a106eac1e9e50498e2b35602d78ed941ec9b3b00940c09960279d86025241e9fbec292528e7351cc5f7beaeee1bbce3cd91c6c29b", 16).unwrap();
        let c1: BigInt = BigInt::from_str_radix("7f05373f50ce8581a2aec000aaea32b244057ee699a7bc84ae286b975e3b80b792ce6d74ee6de09f7680cf63464d4ea20d10b54b93001ff445eeb2a2a5fb85ebdef82fe53961cd263a7ae4ed1553dd0d416a72cb378de6c4a7ac03ab3b65574429dd5a14001c6b9ae7ea9950c2f5a254799dd15bcc85c05a44e7ebaba907b32bfa7eebf28ba75f2e38c80d22ea430fa958b31d019b62b8790f2659853d5f9ae97022e845848cad5268aeb652d53a5746044d19c4fa2137e6b21ffb788b474b85150cd9f87880954cb7dc871fdbd759d6029ccde5ea57161241de057e84bb677171a8b35c110044d778b6ef5b1fe50e78f88226b6aaf4b6e7592f8324708e1400", 16).unwrap();
        let r0: BigInt = BigInt::from_str_radix("1428fc9f8c6c436c6e7c66bc29b10fa0fb9aa8fe31ccd06d3ecf30211764c478eca9a90f94e8358f8ccf255568a1e5b5dfcd35b24c5ab7c6d594e04e00a8cebcbdefa8c0982bacdcf78d31d1ef3e1606cc5edd84d318d52d1c2f1d90e5bd37b07014251364f0a9380b62f520a4af7abef8a5230b77fe0e3b6afc019171a6dca9153e416e9ba5ff0cfbacbf9761eebd6ce7f0c26c5412404c211d36bca307b5f669d864a9f24435b32d58cdebf74f02a09a2cc9f1cb62f81a46532f46ea34b05e0241ebfeb235271596388aff737803dd39d034f9d2ff63bb0aa6fb8d5f25ece525100986cc8b3624696238af415f51f7255ad4e9c92e0df1c5c6c3ad162ca3", 16).unwrap();
        let r1: BigInt = BigInt::from_str_radix("7bce661ebab18abeba4e7beb78515b19f670069cd41ac0d147ec796b3bfd1a3b0111ccbec76b29b59b8ce581217f54b332f30b1835dfb7d96e6a4ec5f17f070e9b567c86efb96a1df3aff158392f33ec9931df8fa106aad8227150b711625e3036e5d07b0ee0efe29ab2c222d73524d5e4ffc215f1a28ccf955769863f6c5f202c4f36b88518f3d7b2998f33c6778057d8888381b1771d464228afd57affc4441e40aed7706be82163820ec793186ddf6d4a123d98ced9f2e3fd8d73cd7ddf791ad46cb64d0ffc500aa8bb5d5a620f9125c1e95e3fc035656cd747b4bba93f4f1cfcc7440a91016fc94834413fd490ee9412237af9e102a66decd6e4805de073", 16).unwrap();

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
    fn test_ballot_proof_2_generated_in_js_lib() {
        let unique_id = BigInt::from_str_radix("f6357c14c3d573f308c3b6cd028d284a7cc332ce96ab2c2836a56cb3a0f91600", 16).unwrap();

        let h = BigInt::from_str_radix("c1d443ca84318828fa9f7542ac74b13fb45fc44bf49c73c28281704479475e5326dd1a86eb7deca46629fb1c5b4a081b30088660b29a82d26e9194df6be3153dea8266706e47295c2846934e45e3f9d6e51a103fa6975015e9923c31f4c72d5b", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters { p, g };
        let public_key = ElGamalPublicKey { h, params };

        let encrypted1 = Cipher(
            BigInt::from_str_radix("341c9ec6e25448efc6e411b624b7504ae922f5fbdebc43b2c7401f6b302db041cdb915bef97f5cc68651da931bc97054275c3ed4104b6515271fdccd3779718da429774d6abca7b4cf0c0f8c13f8a35028ac583ca7e34b2ead14511265e2577d", 16).unwrap(),
            BigInt::from_str_radix("e9699b2ac72ab316663636de79aeafddca6c56485ef2f89dad684c9046da60ca4a6e7ae81767f39f258a3e759c8d890020ec1605796e9b549d5a8d8162b13fb1e7b8d58ddb87e6a855b086b02287d6331b174eb5a75ce090020a4cf71583b4ef", 16).unwrap(),
        );

        let a0: BigInt = BigInt::from_str_radix("5f31df3504caaf32da51dd7db271f6d349cd486e1b6b622122f1b5fa5b83d37369631e90e5bd98da836ef61a724a8864a6588630a9cdfc771e06fe639b124a320e4679b9042617e17ee052771e2c95003855c91df212645490ae3d75dd8f8439", 16).unwrap();
        let a1: BigInt = BigInt::from_str_radix("ccc32b68e512716955679f30296e7a9e49cafcc98df422ba0e48b1d5d379d35412023ed35568fc097791f457d981745a8856de01269ec09c99fad62ab5cca30155224d7ab927ea2b77a63ad5dfdc7d5967659fec02dbecb90e0d8e7194ecc4d4", 16).unwrap();
        let b0: BigInt = BigInt::from_str_radix("648f42198b1c3c84191568523c117d02b126f9027112c66b2070cd2ad9fc6ccf0d7a0ddde708b9c2a2e94dc7d0a133dac8952850c8baf65ebfe2549f99e0920df04c823230c16fbb52126c15615f723790fd40f56f987bdc965ed03db5109e4f", 16).unwrap();
        let b1: BigInt = BigInt::from_str_radix("70b228fe0af7783295e61566970de61d6d587cb69bcaeb2cc15d5adcf7a33f3f8763489dc7c49658b3a38260d7a64e3dc01a2f0855dba9e552ae741fb01c4274b0efa378e1ae5d4dde7f6c43e77491ca51e750ace28722ea89a1f7ef8821002f", 16).unwrap();
        let c0: BigInt = BigInt::from_str_radix("7166641571fed9300d61aff390d291f7f8465111ecdc40836dd40206bd2a005aac1c5ab0f977f9399556a25a5ad967b923d2af26cd9df85c0c0017d68a6e84433133c679b2c8626812c2f9efb532a35986f3895cebded5b373e5669f0b2481", 16).unwrap();
        let c1: BigInt = BigInt::from_str_radix("26", 16).unwrap();
        let r0: BigInt = BigInt::from_str_radix("83e3f77f37d20d7e3220826029fe2728600001c3b6877bbdbeb7628a1715b219cdbe634445aaa6a63a1902e6e152af6fd83b0450f1772250fae91db8e396008c6002a1541e40816e80b1f4f2c256cc7363ecd7790b41ac21bf89b0c891707c", 16).unwrap();
        let r1: BigInt = BigInt::from_str_radix("2488f6ea0d237a502ef8d500f3d3d6cd014c84ea8977a6218386ff7f68bb515fded1e553703c7cd57e987a0110ea64bdd540b9d1315d1d390ba3dee4b7e0611a25fd2845a94976426c671168cfc2131682c68bb912e08c34d4eb3c251dbb0dcf", 16).unwrap();

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

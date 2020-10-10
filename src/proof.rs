use blake2::{Blake2b, Digest};
use num_bigint::{BigInt, Sign};

use crate::elgamal::{ElGamal, ElGamalPrivateKey, ElGamalPublicKey};
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

        let challenge = Self::hash(&unique_id, &public_key.h, &commitment) % &q;

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

        let challenge = Self::hash(&unique_id, &public_key.h, &commitment) % &q;

        let lhs = generator.clone().modpow(&self.response, &modulus);
        let rhs = commitment * &public_key.h.modpow(&self.challenge, &modulus) % modulus;

        let first = challenge == self.challenge;
        let second = lhs == rhs;
        first && second
    }

    fn hash(unique_id: &BigInt, h: &BigInt, commitment: &BigInt) -> BigInt {
        let mut hasher = Blake2b::new();

        let arg1 = unique_id.to_bytes_be().1;
        let arg2 = h.to_bytes_be().1;
        let arg3 = commitment.to_bytes_be().1;

        let concatenated = [&arg1[..], &arg2[..], &arg3[..]].concat();
        hasher.update(concatenated);

        let hash = &*hasher.finalize();
        BigInt::from_bytes_be(Sign::Plus, hash)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RandomizedProofParameters {
    alpha: BigInt,
    c2: BigInt,
    s2: BigInt,
}

pub struct ReEncryptionProof {
    e_prime: (BigInt, BigInt),
    t2: BigInt,
    c1: BigInt,
    c2: BigInt,
    beta: BigInt,
    s2: BigInt,
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

        let challenge = Self::hash(&e_prime, &t2);

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

    fn hash(e_prime: &(BigInt, BigInt), t2: &BigInt) -> BigInt {
        let mut hasher = Blake2b::new();
        hasher.update(e_prime.0.to_signed_bytes_be());
        hasher.update(e_prime.1.to_signed_bytes_be());
        hasher.update(t2.to_signed_bytes_be());

        let hash = hasher.finalize();
        BigInt::from_bytes_be(Sign::Plus, &*hash)
    }

    pub fn verify(
        &self,
        e_minus: &(BigInt, BigInt),
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
        let c1_e_minus = (
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
        e_minus: &(BigInt, BigInt),
        public_key: &ElGamalPublicKey,
        voter_public_key: &ElGamalPublicKey,
    ) -> bool {
        let params = &public_key.params;
        let modulus = &params.p;

        // E(0, beta) = c1 * e_minus + e_prime
        // lhs
        let beta_cipher = ElGamal::encrypt(&BigInt::from(0), &self.beta, &public_key);

        // rhs
        let c1_e_minus = (
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
        let challenge = Self::hash(&e_prime, &self.t2);
        assert_eq!(challenge, c1_plus_c2);
        let first_condition = challenge == c1_plus_c2;

        first_condition && (second_condition || third_condition)
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
}

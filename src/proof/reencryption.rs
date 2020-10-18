use num_bigint::BigInt;

use crate::elgamal::{Cipher, ElGamal, ElGamalPublicKey};
use crate::hash::hash_args;
use crate::math::mod_div;

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

#[cfg(test)]
mod tests {
    use crate::proof::utils::create_crypto_material;

    use super::*;

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
}

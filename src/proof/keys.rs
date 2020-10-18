use num_bigint::BigInt;

use crate::elgamal::{ElGamalPrivateKey, ElGamalPublicKey};
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

#[cfg(test)]
mod tests {
    use num_traits::Num;

    use crate::elgamal::ElGamalParameters;
    use crate::proof::utils::create_crypto_material;

    use super::*;

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

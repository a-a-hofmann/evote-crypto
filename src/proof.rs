use blake2::{Blake2b, Digest};
use num_bigint::BigInt;

use crate::elgamal::{ElGamalPrivateKey, ElGamalPublicKey};
use crate::math::{mod_div};

/// Schnorr Proof - Key Generation
/// Proves knowledge of an ElGamal private key `r` that belongs to a public key `h`
pub struct SchnorrProof {
    challenge: BigInt,
    response: BigInt,
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

        let challenge = Self::hash(&unique_id, &public_key.h, &commitment) % q.clone();

        let response = (nonce + (challenge.clone() * sk) % q.clone()) % q.clone();

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

        let challenge = Self::hash(&unique_id, &public_key.h, &commitment) % q.clone();

        let lhs = generator.clone().modpow(&self.response, &modulus);
        let rhs = commitment * &public_key.h.modpow(&self.challenge, &modulus) % modulus;

        challenge == self.challenge && lhs == rhs
    }

    fn hash(unique_id: &BigInt, h: &BigInt, commitment: &BigInt) -> BigInt {
        let mut hasher = Blake2b::new();
        hasher.update(unique_id.to_signed_bytes_be());
        hasher.update(h.to_signed_bytes_be());
        hasher.update(commitment.to_signed_bytes_be());
        let hash = hasher.finalize();
        let result = BigInt::from_signed_bytes_be(&*hash);

        result
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Num;

    use crate::elgamal::ElGamalParameters;

    use super::*;

    #[test]
    fn generate_and_verify_proof() {
        assert_eq!(BigInt::from(4) % BigInt::from(3), BigInt::from(1));

        let params = ElGamalParameters {
            // 2048-bit size modulus
            p: BigInt::from_str_radix("F52E0A34AA46657BE51CE1BFEA30D0BE7FD65D879AB9B2CAD7CDFECE734F074065869ABFD3B9FF77C77ACCE7824F75BB51D8BC0A2D83974D3CFE14100375C9DE52C4C038FDD03B4BC30616EE1997E7D5AB108DA95BEC7B7D5394781B2CE85000D8A7A02306ED48F7242D0277A8EE0DF0ABAC3725A9349FA4F1883D89FD5A027D97670368369B266F4BCDD1D4F266303580003FC02B82B97B86674D7387083143583ACA5C5AA63A86D6C88CF95F203203DCFE726C0098790B2B64AE3DD58ACDFDB912A75688B593F9D1342D49408ACAE04B184DA61976FCBF87F0A608CBC7F7B152D57C0F2F1E090A55EFA74E49BDCABEEF9A59EC9BD3D89FC8BBD920D5CA1CED", 16).unwrap(),
            g: BigInt::from(1035 as u32),
        };

        let private_key = ElGamalPrivateKey::new(BigInt::from(174), params.clone());
        let public_key = private_key.extract_public_key();
        let public_key2 = ElGamalPrivateKey::new(BigInt::from(173), params.clone()).extract_public_key();

        let unique_id = BigInt::from(123456);

        let proof = SchnorrProof::new(private_key, BigInt::from(17), &unique_id);
        assert!(proof.verify(&public_key, &unique_id));
        assert!(!proof.verify(&public_key2, &unique_id));
        assert!(!proof.verify(&public_key, &(unique_id.clone() + BigInt::from(1))));
    }
}
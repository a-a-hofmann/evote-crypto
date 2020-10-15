use core::ops::Mul;

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

        let challenge = hash_args(vec![&unique_id, &public_key.h, &commitment]) % &q;

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

        let challenge = hash_args(vec![&unique_id, &public_key.h, &commitment]) % &q;

        let lhs = generator.clone().modpow(&self.response, &modulus);
        let rhs = commitment * &public_key.h.modpow(&self.challenge, &modulus) % modulus;

        let first = challenge == self.challenge;
        let second = lhs == rhs;
        first && second
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RandomizedProofParameters {
    alpha: BigInt,
    c2: BigInt,
    s2: BigInt,
}

pub struct ReEncryptionProof {
    e_prime: Cipher,
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

        let challenge = hash_args(vec![&e_prime.0, &e_prime.1, &t2]);

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
        let challenge = hash_args(vec![&e_prime.0, &e_prime.1, &self.t2]);
        assert_eq!(challenge, c1_plus_c2);
        let first_condition = challenge == c1_plus_c2;

        first_condition && (second_condition || third_condition)
    }
}

#[derive(Default, Debug)]
pub struct BallotProof {
    a0: BigInt,
    a1: BigInt,
    b0: BigInt,
    b1: BigInt,
    c0: BigInt,
    c1: BigInt,
    r0: BigInt,
    r1: BigInt,
}

impl BallotProof {
    pub fn verify(&self, cipher: &Cipher, public_key: &ElGamalPublicKey, unique_id: &BigInt) -> bool {
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

        let rhs = hash_args(vec![&public_key.h, unique_id, &cipher.0, &cipher.1, &self.a0, &self.b0, &self.a1, &self.b1]) % params.q();
        let lhs = (&self.c0 + &self.c1) % params.q();
        let fifth_condition = lhs == rhs;
        assert!(fifth_condition, "5th condition failed");

        first_condition && second_condition && third_condition && fourth_condition && fifth_condition
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
    fn test_ballot_proof_generated_in_js_lib() {
        let unique_id = BigInt::from(123456);
        let nonce: BigInt = BigInt::from_str_radix("2644dc5fa5455deca31433b6247a914f2f287045914dced014b98a3d09a3616b072b5629a04fd37df6a2f4735a3c5ad1fecc32800c1beb2472d3419048b303c0f33a3e40b65482d10f134a4a1f2fe4f6d10eeee99313cebf1684475b493dd7c7009a93701d6299d2e40e9139143ef32fe2747702b35d0d162a43366c4006b8804e5355eaed00a6a59e65b4e31bea5af95fccfae5c631ba6403894d72c119afe75bf9e7f9c4f75347cefed7b6a822752cfa22e269898b7eaac4854d0078ca41618c9f7fafab0886b7c0ebb2ff25c2831b9c6e204de1b531f21099ea3ce937114cf2b847c1b7119be3f1e7e5495e7c52c1565864c8dfe76fa8c30cec2993dd28", 16).unwrap();
        let encrypted0 = Cipher(
            BigInt::from_str_radix("410f54603dc001a046697939d3e3a9db160f05028b9aee960b5a87e717c2b36ac268bba358cc82a5f34b036f0b34524c4c455337360911517276c92bc7201662c74e8464d705a0d5bf94fd75fc5879a1cf0c4fdbde455ea7d2d02e6ad1ab8b4c58444d0f421bc707847057040f8a336e64ddebf990a0e49dc8cdfaf2f5961b76a1c706c67c57a39355473a7ab81a952afc76e4edb3275579ed1eabcf96311b0646f8641fecd414dfb741038e5cf748bc1907f0948bd3c17096e7b7fa321c84e1046ab9d088dec44fc69f54181e269e3b7b6f3232435837cf6760acd6af7a58b4acb2ae19b69ad287d218fcbb59dee3653f5b9a3fcc133862a1b107cfc6543884", 16).unwrap(),
            BigInt::from_str_radix("b5eb4638b10dab051d9fb45d474c753880cd62a61a4f1b4c98c79a710f4c996412c2d09eb8d1fbd8cd7067a3fca9d53cdb64d06bbe8162fa41c03366a914be9718ef5a79d57b0af16b815709af28f21d14beb8bf76eb3b08607c952c969736e47d6ddcc2789cef3a84a0f705d20d5c0f62055b4bc82d734fcefa9c2ce40f2114120e07e868a89b43b0cec54a40ebba1fed7bff0d1be25e172df3e944f5091ea92742456ce4cb589f47ad20de9cf976e2a09d42f2201293b53d212eb79ff83e4548a7ceba375a442485dbb1b2ad0e06110b8a569ff6e339a3150fb0c776b0302cc12866a40109dbf21e8ce6a6da80634733fe892dbca5e38b8cea6f5b1af71166", 16).unwrap(),
        );
        let encrypted1 = Cipher(
            BigInt::from_str_radix("410f54603dc001a046697939d3e3a9db160f05028b9aee960b5a87e717c2b36ac268bba358cc82a5f34b036f0b34524c4c455337360911517276c92bc7201662c74e8464d705a0d5bf94fd75fc5879a1cf0c4fdbde455ea7d2d02e6ad1ab8b4c58444d0f421bc707847057040f8a336e64ddebf990a0e49dc8cdfaf2f5961b76a1c706c67c57a39355473a7ab81a952afc76e4edb3275579ed1eabcf96311b0646f8641fecd414dfb741038e5cf748bc1907f0948bd3c17096e7b7fa321c84e1046ab9d088dec44fc69f54181e269e3b7b6f3232435837cf6760acd6af7a58b4acb2ae19b69ad287d218fcbb59dee3653f5b9a3fcc133862a1b107cfc6543884", 16).unwrap(),
            BigInt::from_str_radix("6bd68c71621b560a722f8e186d30283c3cd462c0b3c219c8088ce6d9943166542379e29736905c8f4996c6ce6b1fa59bc7348723afc882d953555c5f5fca68f6e1fd7f863da4539cf27cf89cfbf3657335312e95479e88a5b4f9cda23927b5db0ca34d8996b03ecf5aa2c9fa27cf98387ae25045a3768b61dbf4bba126ba83228b41c79ab4fb62ecf8874aeb84b2a4e05792a0f65b210e983f84df33c98cea96afaf61d259001ad1284e0c6eef3655c04fc619db760d05ee47b1ff2911b9ae4eadb1264856a60245708fdfc26e146992614f4f4f7e7a207c4bf395985808494148bb83cb177e4cff2747a7351c06c17e528a8400ee9f1cae19d4deb635ee22cd", 16).unwrap(),
        );

        let h = BigInt::from_str_radix("e450fde21b1a160dee9f1576f0771785182579b7f49777bcd6950acc3e06fe10330a5eb4f18f29c95076d81d83748ec19b4e7391f240765d268d601abb89ba7a69a5341a2a77bb356fbdfefb495f2820b5d213217e8db987f7ebc212b8c057702dac3cd293354ec238c5e3f55bced02bfd700efd78ca3ab128c863ae76c8e9a646ce844b0502994d3c2dd2d251c839a7570b7f36daab13fcad4ddc09d95cda51381b4f84248d7e24b6caec06664afa82b682fe1295a67ebac76dc8ea25f33836b64e9a09359f456da262bdafef43fb439224888710952bb312c1dbd3b2ff9a9b5ba8765a2a761171025f004c1a0b50dbbf7d6aab001632e4f526d1a1488964c6", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters {
            p,
            g,
        };
        let public_key = ElGamalPublicKey {
            h,
            params,
        };

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
}

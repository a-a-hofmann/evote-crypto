use alloc::vec::Vec;

use num_bigint::BigUint;

use crate::hash::hash_bytes;

pub struct RSAPublicComponent {
    pub exponent: BigUint,
    pub modulus: BigUint,
}

pub fn verify_signature(
    message: Vec<u8>,
    signature: BigUint,
    rsa_public_component: RSAPublicComponent,
) -> bool {
    let message = hash_bytes(vec![&message]);

    let verification = signature.modpow(
        &rsa_public_component.exponent,
        &rsa_public_component.modulus,
    );

    verification == message
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::Num;

    use crate::blind::{verify_signature, RSAPublicComponent};

    #[test]
    fn verify_message() {
        let exponent = BigUint::from_str_radix("10001", 16).unwrap();
        let modulus = BigUint::from_str_radix("82a90eb3ede945849547f418ad2f02c22036a55155f8096bd5b8e6d6f9ef31e996131c4c4a881eebfb20221c2ad59a064ceafb0e4b373aa7ad163b8c2e54ea6098cce05decb9bc415f18aed866b74d01f248ac3fd000d9825b1c9c778f98a7a8428a1954e3675c88f45696aa96063dba8fd1289654d0d96439ac654aff6c632cad268c3e814c2575a5971567f291074d0a39ed6f0c057afbc939aff6dff5647782d51a6be58a41672a389322f0ceb3412e222ee6eae9e7d6d78ebc642ebdf985e106101e8e40ea6eb62bf01f667ff4994217e6e21810cfcf0e845bb79abe79b1b1e5af5535568bca91abea68ec6a52dc15dd29e372ac3f7c54c5ba451b2e2815", 16).unwrap();
        let signature = BigUint::from_str_radix("3da5fefe80ee46dc35cc246a2925d7275cac1724230beeb7a9c46defecdc68a51e8f1de4a3446e1eee8fde610d87485a55f92c33f6924f711588959ca7e3bce7a9c8b004b0adf821a84978fe7b8a4841405ba9f2c583507b1f420fa2e3659ef30f2f7f1532a44e4f1b19afc0d6fcf5686e5a1d4b27dc797e53d9e3b1ebc2d3a0a4696f6e9c2f7974b83c3da2a39b8f1b86634a81dc08153a92ee4a1569fa6fdc2530fedc8ade5c53ec08643d8ae36fa39656eb7913d8cf02c9763bd942e4ec3ccc27959cf5bce05bad4886736c597d4baa84371aa8435504060e38ada303acc581c290a98ff57dbf39f639ed4f13cfb91657dc24405a9d630e03375955cc2ef0", 16).unwrap();
        let rsa_component = RSAPublicComponent { exponent, modulus };

        let result = verify_signature(b"Hello Chaum!".to_vec(), signature, rsa_component);
        assert_eq!(result, true);
    }

    #[test]
    fn verify_message2() {
        let exponent = BigUint::from_str_radix("10001", 16).unwrap();
        let modulus = BigUint::from_str_radix("e97a728532da5af885d0fbfc2dbe97854eb7765e209ed8c426092c8c9f22a60bf29018a8c8a86f7957e5dba77f95bfcee901fc8d5a633b60d0a6bb7bc7f6bb63edf229872d223d87b133875161c2502c099a2731a6567346e339eb5fa73460516784eaa1c96eb37270744a152c8908a1cc73aab10608123861b8a466abd5f6f230a11d935675659bee231c61f763f13b192181d40aba657da2693b07af818e472919dbfc756fc2eb59f4e6cc077e6cd2621f3688e4af6a4567d2b9cf55261a8b92733decbbd48ea9a1603c7dd9ed89244bfc54e1007bb429392f9577615dad735b89e3b3f0dbd5d30becbc0ceedd4d1071dba4f141f6961f14cbc671c7babbdd", 16).unwrap();
        let signature = BigUint::from_str_radix("338a3c9c2db0aae1047a452055f28458f50f6efcb95bc5eb82e43aa8265ee13ba13207143be30a7627cf7239e65cf5bcc6598449de7619fa756d159763b262543a6a47fac0d3bad2533caf1ec40d5ce0aba91ce13ca298bd71cee2aec3c7acd71532a67ef8fb6e3da6a1ac3b38873c4bc604a79c4ab974f073f3a6de4195b16beb2b5878a14d13576cafcd08b5d53e8c125746588a9629b637cfa288e48b70d2dcfcb5ba7a35f10c9997b86a6944b5fd4120afdfa4ef5ef9f0bbbe4832032defedb1fde8e517744b388978377a31ef89662fac841b4ec9197fa685031d679e3d6070bff0b8f58b98cfaffbdda9146cb0739e171de2f5585afdedfb8886d5b19b", 16).unwrap();
        let rsa_component = RSAPublicComponent { exponent, modulus };

        let address = b"0xae3a3e13f0028a514bab665e1d207bea3507a14690fd5bc887e30abcd9f99d71";

        let result = verify_signature(address.to_vec(), signature, rsa_component);
        assert_eq!(result, true);
    }

    #[test]
    fn verify_ss58_address() {
        let exponent = BigUint::from_str_radix("10001", 16).unwrap();
        let modulus = BigUint::from_str_radix("e97a728532da5af885d0fbfc2dbe97854eb7765e209ed8c426092c8c9f22a60bf29018a8c8a86f7957e5dba77f95bfcee901fc8d5a633b60d0a6bb7bc7f6bb63edf229872d223d87b133875161c2502c099a2731a6567346e339eb5fa73460516784eaa1c96eb37270744a152c8908a1cc73aab10608123861b8a466abd5f6f230a11d935675659bee231c61f763f13b192181d40aba657da2693b07af818e472919dbfc756fc2eb59f4e6cc077e6cd2621f3688e4af6a4567d2b9cf55261a8b92733decbbd48ea9a1603c7dd9ed89244bfc54e1007bb429392f9577615dad735b89e3b3f0dbd5d30becbc0ceedd4d1071dba4f141f6961f14cbc671c7babbdd", 16).unwrap();
        let signature = BigUint::from_str_radix("d53aeb427e94c03ddd7eb38454e3d32ef04abf0a154bd819e4b993e9f648c755ea921cc2070bf67387b089946f3814c1e13436dd52885b697854545e5d3d9442cb74f9be6393f6def6513be89362e7e08f8fbbd0d9c2932612f16d2b1275dea725d33125a6859830852866b35e0992fe1450f59d8fb2f06b16f1f781285fa46eac566435057cbacd0ebf8e53822f5f166cb6061437fa7442351645fe1e46ec7abe71a83048e5da649654337699d0882509d154448c07db652575c8f5005aa031a57262df9c54bc453f2534e6d93277e3f269af4f36a3a60414eef83f973a8b630073d2e827e8e7c0214dbc038926964e40c4fc22f3081072c81bfff53da69352", 16).unwrap();
        let rsa_component = RSAPublicComponent { exponent, modulus };

        let address = b"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

        let result = verify_signature(address.to_vec(), signature, rsa_component);
        assert_eq!(result, true);
    }
}

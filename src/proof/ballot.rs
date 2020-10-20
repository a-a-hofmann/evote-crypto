use num_bigint::BigInt;

use crate::elgamal::{Cipher, ElGamalParameters, ElGamalPublicKey};
use crate::hash::hash_args;
use crate::math::mod_div;

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
        wfs: bool,
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

        let challenge: (BigInt, usize);

        if wfs {
            challenge = hash_args(vec![
                &public_key.h,
                unique_id,
                &self.a0,
                &self.b0,
                &self.a1,
                &self.b1,
            ]);
        } else {
            challenge = hash_args(vec![
                &public_key.h,
                unique_id,
                &cipher.0,
                &cipher.1,
                &self.a0,
                &self.b0,
                &self.a1,
                &self.b1,
            ]);
        }
        let hash_size = BigInt::from(challenge.1 as u32);
        let rhs = challenge.0 % &hash_size;
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
    use num_bigint::BigInt;
    use num_traits::Num;

    use crate::elgamal::{Cipher, ElGamalParameters, ElGamalPublicKey};
    use crate::proof::ballot::BallotProof;

    #[test]
    fn test_ballot_proof_0_wfs_generated_in_js_lib() {
        let unique_id = BigInt::from_str_radix(
            "f6357c14c3d573f308c3b6cd028d284a7cc332ce96ab2c2836a56cb3a0f91600",
            16,
        )
        .unwrap();

        let encrypted0 = Cipher(
            BigInt::from_str_radix("7c0c38fca8eb93daa862825a21b552e178a2edf8e07c20fcfa6b0dc90fe1f6a53460fed1e667dc5a5f41686e7a75fad9a1e929bd2551f55789dbefbe79948bf865c2a26b57f80d730fe46adb3597b0a268dd0bbab20266d85aa7718c93091b47fc66c78bb1b712602632564100d7826de4bbd4cb06e165132fd9033deb88876dda591b5211de51a0674a389c672a87c7ee345c6fc82766ce4f74e4b28a093af0812b8fa3d2b71dd4d8e6ab1d2f996ff0bbf508c7ccd83344ea3aece9abc46fc5ba9aabd025093e48ccfc4c7bc350c88317f4e207f09352b71dc721edbc7d311f39c5bb947317fca49779f349c258c6093257038117888533b91d3cef8256e9e9", 16).unwrap(),
            BigInt::from_str_radix("690715c31aa9855095f97278eae1abc82940b4e453b9f1e7db64a38f4e239a3e043094b024a1bc73e656cb308a3c135c1dad28447c63dc64747883c4ee19c1b5a7dc268d0bd81b2f187c7124c6262dd50726b6b99bb4952fed7d7b0d5ba451554b4123e132d90bd29590f6be4423974a349ea5aedddf02501aa7986b3147358c215cb6263b33100163029e6e590e7e5c28ac215d3bc8b53079b53939d205ffc4b5eff6d666c41f8bdc72299fcdb4066644de098b6e5e5c798dac06322597e1b7c8c7a7474e1766b49891b7a60bc4d41cce53a90b7cbd9b6056a5a8a2dcd95e9fb09af8ab76f67fda72b6f1c3d3124578bed653126aeedd66023591f868c9ec01", 16).unwrap(),
        );

        let h = BigInt::from_str_radix("2062d017d762f8b88c245d7e241805df84ae29232fb36f6138590a42c6b47d4a81ff072ce7e6d8741f8b56fe8165642754765fc483a730de3b4860674ccdbe060c3a7e810ef3e3f4b28dd095fe1f61ae20c588aef0b06455389eef64ec927ed37a46ca95ec48ced4abcfa74611e29065487178efad87f494d55ab3e152a0cd8923219c9ffc69c94ecafbcede1e267e55cc9051ea6b9e99062393147ea39296c9d0312a7f4e8017fda8dbab3f029849eeba601aac5bc74fcd47fe9e9ce1510df902852ddbb1180566fe3188d646a281f89421782d3cc076996f3cfef8999827c7630a4d90290dcae6d683f223d1d7f85f91a096720e44ba05c8b2b62b27f5a31a", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters { p, g };
        let public_key = ElGamalPublicKey { h, params };

        let a0: BigInt = BigInt::from_str_radix("c32b48940e2b83a2aedded083a4c85ebc5cb2f72ec72bdfab810fb9a9fff9a2c0e506498bafde9023444c2fe8fd836a9f1cb550f52d60219421910f43a47f64280256006a0e7644818d6af3f8d4f0d2f282135b39ae2d2ceba788fd349dac80da981f16ed0ded8a8cd369ad57a7a167cb4dc8d68044f832c5e3f89b6c52df2afd56fb95f6dd53adc5f93cf3e52a08ccde4cb9ad512eec59e57578681b9d43f517b5e632f7dde92d311e0197ecce9e26b157e8b0e93a514213206ebc981dbd21ff82f4f6aed49faf164cd87d09164d88878f9192836acc8d00aa737ef915ee46662554b1246e178ebb9b0e1e1dd50e22538dd6781308943e4034fd8685d8df97e", 16).unwrap();
        let a1: BigInt = BigInt::from_str_radix("5010c5a97aba698d909cec584e2108874abe936bfbb43fe6e3e27e5b3ac16388f2ed11397010f9d2ed31c5463e08d21c6b42cf036e7db5c37ce478015a90349fa80799196d5bfa3b57e08bc2fbf9da9f956c8e0ad33422cb6f7d153ef223748033f8dabb1c1afe550f68c0e0192c7821c1161023806989f02b0d2a96c835e04d5c9de4a8e10820d2a0bd3c6ebbceea2f699c683a929f586a410bc3b8539708905b2f9b20a75bd259156aae098c28b551e2eddae1c4ac5abead916ac20ced87397fba8bd3e6edcfaee1d79a4df4380c2a0330c64ac35d294ee8e3973e09fc40d9e9624eabbb241afef7b02bd49864a9ed158b74f249a26ef9a44cd0668726d990", 16).unwrap();
        let b0: BigInt = BigInt::from_str_radix("3939ab608a3d31b4e827bc5df6a9160abd1b8652986ba24d73a06c7f91c4262a01c59b1c8251c94226536c2100184240e470a9e90b0e52f894bb8b6e28736b76d02827920e79a40b108d9ee795e25964205221bd5aefef86c3c4f285fa80c48f9864c01c4541a0c878c7b78df0acccec2b21118d4a38c89b0940005b760d5faef37241a62e719f2f147628912cdce4badb33ffbd603fbc3930d9513e55624929509ef22c224fee19f5a7dfe0e34467d73bf7c8540512b5237e7ee82965a6f6e6e812fe9101e2937c12662eda52bd4852c900c8d9f9add09c78b354408f835eb8d95fdc7551f554cf6f8d626c142f41433086c690490b59479edf1da0d12ba4cf", 16).unwrap();
        let b1: BigInt = BigInt::from_str_radix("312c1161a61e6e2f9303a11f5a7480e760ac3e4a8025821b53bd42ccc30d89c395727f9a84605680117213b45ae5129154ba581173656cf2f749ed2ad31edb19ada541e5b2fff1d75a19bc6de4fab267f4d56bf174173b78e51c88ce84c1a1fa31853ea8d4b6f92d83ed158b4cab460665bcc4022d6c29033b3985116d83c9442ff0747fb8c843a79bef650da960e5663eba102ab3767c1a0bbaa63f7502a12a3485b3fd9ce885d767fdf9ecf61b33a49c21e55aa4b3a1402ff5b8616e1c6668ebae7ba001d9da1b3b00043a1e24a3fcbd83e713688505bc9c56ef9b804c184e594a5d272991029b364dedb2aefbeb98184ed8a9cccc9e0221ff9d7650714030", 16).unwrap();
        let c0: BigInt = BigInt::from_str_radix("11d", 16).unwrap();
        let c1: BigInt = BigInt::from_str_radix("74", 16).unwrap();
        let r0: BigInt = BigInt::from_str_radix("539e775b0d5ecf4ded87606a61ec11f6d68490c8861c9ce0212807f04a7feab9575ae34e9adfe9fcba68684187b46bbab45414c408e371c73e5422885d7436d281845bd621a1cccb01f7421956f7815932462eeed0ee07939d515267aac1fb1ca5a2bbe1a638ef1633baa43501f0cd005cdae6b8849ff5936ed1a81afce1fad616d101a4db0a56eb2224397dc4bf2486b8417ec90a0b99487edd82b4ffa27aa340192b751aa845e2d88e7ff4373bf79ff160c7fe05da627a258217769ccb4a3228edc01cc53b29a3b43932c1331a8dd04474bce5cd5b36fc6e58eb9bbc54dc67b7bd04d1a6deefa4b57b8a5af814af1b8fcb5973d7ed2308c37006de3af10442", 16).unwrap();
        let r1: BigInt = BigInt::from_str_radix("df8116d52abd7dda39006cb27e7473acc8a768ae3f09346faabd5c0b7ea05bff281ffa2df1522d5db6135127d5574b97748abedb99ee38f75ff386066349884dce29b0d204f69e9aecc20d17e543f7c492ce132f7292a25ecb07a078a860d076bfd63d6e354258b7210c6a69fef079bcfb3a64dc199592683b48daa88ced3829fbacec4839154541e4aa4e004c670d4f86ef54fd02c5968b5f97dd7b392c4cb2b51cea5434751b85f36657700fea872812f87f7762f81c18bd38e99414a0f573937d4e78c4013f6abf43b500589facf7330073872846a1770b804b9011b5adc4166615f4e76058352e2cdc3d392f12bca575a4c4a1fce0d3cbbd32b3e1a5aa", 16).unwrap();

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

        let verifies = proof.verify(&encrypted0, &public_key, &unique_id, true);
        assert!(verifies);
    }

    #[test]
    fn test_ballot_proof_1_wfs_generated_in_js_lib() {
        let unique_id = BigInt::from_str_radix(
            "f6357c14c3d573f308c3b6cd028d284a7cc332ce96ab2c2836a56cb3a0f91600",
            16,
        )
        .unwrap();

        let encrypted1 = Cipher(
            BigInt::from_str_radix("7c0c38fca8eb93daa862825a21b552e178a2edf8e07c20fcfa6b0dc90fe1f6a53460fed1e667dc5a5f41686e7a75fad9a1e929bd2551f55789dbefbe79948bf865c2a26b57f80d730fe46adb3597b0a268dd0bbab20266d85aa7718c93091b47fc66c78bb1b712602632564100d7826de4bbd4cb06e165132fd9033deb88876dda591b5211de51a0674a389c672a87c7ee345c6fc82766ce4f74e4b28a093af0812b8fa3d2b71dd4d8e6ab1d2f996ff0bbf508c7ccd83344ea3aece9abc46fc5ba9aabd025093e48ccfc4c7bc350c88317f4e207f09352b71dc721edbc7d311f39c5bb947317fca49779f349c258c6093257038117888533b91d3cef8256e9e9", 16).unwrap(),
            BigInt::from_str_radix("d20e2b8635530aa12bf2e4f1d5c35790528169c8a773e3cfb6c9471e9c47347c08612960494378e7ccad9661147826b83b5a5088f8c7b8c8e8f10789dc33836b4fb84d1a17b0365e30f8e2498c4c5baa0e4d6d7337692a5fdafaf61ab748a2aa968247c265b217a52b21ed7c88472e94693d4b5dbbbe04a0354f30d6628e6b1842b96c4c76662002c6053cdcb21cfcb8515842ba77916a60f36a7273a40bff896bdfedaccd883f17b8e4533f9b680ccc89bc1316dcbcb8f31b580c644b2fc36f918f4e8e9c2ecd6931236f4c1789a8399ca75216f97b36c0ad4b5145b9b2bd3f6135f156edecffb4e56de387a6248af17daca624d5ddbacc046b23f0d193d802", 16).unwrap(),
        );

        let h = BigInt::from_str_radix("2062d017d762f8b88c245d7e241805df84ae29232fb36f6138590a42c6b47d4a81ff072ce7e6d8741f8b56fe8165642754765fc483a730de3b4860674ccdbe060c3a7e810ef3e3f4b28dd095fe1f61ae20c588aef0b06455389eef64ec927ed37a46ca95ec48ced4abcfa74611e29065487178efad87f494d55ab3e152a0cd8923219c9ffc69c94ecafbcede1e267e55cc9051ea6b9e99062393147ea39296c9d0312a7f4e8017fda8dbab3f029849eeba601aac5bc74fcd47fe9e9ce1510df902852ddbb1180566fe3188d646a281f89421782d3cc076996f3cfef8999827c7630a4d90290dcae6d683f223d1d7f85f91a096720e44ba05c8b2b62b27f5a31a", 16).unwrap();
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = BigInt::from(2);
        let params = ElGamalParameters { p, g };
        let public_key = ElGamalPublicKey { h, params };

        let a0: BigInt = BigInt::from_str_radix("c3bc793e8b7fc188a7926b92eb74c96909d0ab3496366f95abb22ff3daa8536fd2c0d13e8aa341d055e2c776c5fb81d9ddfdc605c3c0b0c1ab67519cf7ebfafb746f46f421405e9e98c5c4d44658422f4238d282d40891784d19ae824ac607539be6a14f3f1117a93ed7d04ea8dc5589c6671b82a830b77cd0419e0ac19bd161d06127a7a76877cc254c87648dd7e7073e6564e3088e73bc62d760b17bbe41a472c0a510599cd9ce2173a1d937f81fd1b5f171101d337ee7aeed96cb7402f245003d8ec9a366e05f500c429fe20e2a4338e736710750c1739293661847b54e79239998633928774d248de99d68f2cacaae741c6d216c52da5110f715e491e2ee", 16).unwrap();
        let a1: BigInt = BigInt::from_str_radix("da7ddaf5506bca2e3f383176d4b84d147e800888645acb69e373347d57e9e699d328cd3a0be62d582c006af421960047cbf8ee21e6a7646ba57e471d309c96f6b1270eabd5cc4c3f5f078f1e3970e7c8a57a9aeabdb74581ce344e4ec31551b8c0d77039b8d560fa8445c5ff3defeae44c2368441c495fe4f92d43812ac91e7a41d9ff126bb3ec8621d684ef8a497fd72859e57ff6e5a5d26ad6d288df3a145e7cdcd1fe5394d8d735f4b540931527b8a703e682f70fb95ec94b0d914a7f1374eab6efea22e1c4740b0bc258a38b48ebfbe49527d7764c5a3ca6abe40924c1832bfd075cd6d41d7f0d9db6bd5887bae422064c6c7b5f205203606c9b601036d3", 16).unwrap();
        let b0: BigInt = BigInt::from_str_radix("fdbd54ee2ef8d02abeec203565d653f1769e0078cb9eb6bbdd5293beb74a6bd8cd8ea239ccc80952cf31fde220ac79eab48ff5fd605195217cc42a280eb3c704ab747d60e032d9798384e1d50a58c2038c44a1d152946c90be0d54c0e56cc0839cc0aaefef64823420e4644a61a5e41ebf5e373c38692a6cb202d6d131d5527517e103c05ac1df2712491aa79a4b118bd49c0eb15329fbd2f92078be237a76c4c21e352ed3ff74cc6406c702b75489950962b447751e8b2cdff3d306e89a61667a9f8fbcd8dd466a8b84706d71538f125972789f1b85e9e47e226df2358f4b626baedacd4b38df54d104d2fde103cc13f0d01519a41975eac449087c0e705319", 16).unwrap();
        let b1: BigInt = BigInt::from_str_radix("735864d61864e44266d8f60d877bafe3bba150294db4bfbf5d67984cc5c860d4bdf0495fb79986cf538c58bb984bf3e8d144215cb744b9bd350ca33c509d40aa7c84c357dae4a39f062b12bdb1294e2fff4fb2ae0b2e37e20f1c9edd5100d7317a0f99d842425d0f33802bb861e6a9acf0c33de1011526863a01652d4f0b74ac7a411dd66dee76d67180ee91d044928c679f0222b8230e89d983e446df6a489ef556828c1a8b8360d90d2282132caab89e5ed247fb684718d7dea23259e5eff4cbae47f6d14c3647da2ea1d371cefd1d92cd5815f7be644fd0f161ff03bf8c8bdac626af1fd1e2ed2fa1a4f8ab4ee5ca98f5aca6b86121befe19ae6ac0ad5739", 16).unwrap();
        let c0: BigInt = BigInt::from_str_radix("8", 16).unwrap();
        let c1: BigInt = BigInt::from_str_radix("10e", 16).unwrap();
        let r0: BigInt = BigInt::from_str_radix("715ae5231d38b5a7e1cbcaedd78fd18eb3327d3f62a897b593b042895228750787a9ecf6d02f06adc23af35356249048777f3d7c71eb7cb7255e13e82af1645b89eb8d50e5ce6a8d3e2eeacf3f1f3c83d8e85c9ec0aea5b121ed2ce819e5864295f227fd2685bd1e529bc37995bb7e54f74572ed9beec8b7da9785b73202118a4d4851ec3e5ea613538731f4f7b713d3dc1dc40fc6626b2aee0cc6cf67110aad903564e449c6d3d83f7130201caa00a85738e6c7c42267118613812a1d15cf1f7b9271e1a928b7f0786dd237a855ae85f67724e377d79cd37afa25e1d2bcb9b35ecb9a9ca9157b65350e14ab7f8de80f4d309fb0d9f88ed2c86533c6740cc4", 16).unwrap();
        let r1: BigInt = BigInt::from_str_radix("4f316fda80c144090ed90ae91bbd682ea5357732a19a63241b141fb28cc9d953d33061acf141e78b2a0dcac228ba635b54fb6dd1bccc30fa2f2733f0e0f9dde7ffd32ef16ac0355a4067ca3c66d656acac868186bc14478a08505c16ecafdc9b0136aca223f18e1b456034e9c61d666833ce3308b0918a4d76eb3e6dd59d267bc4433adc9755356565574f0990a6ad997dfdc2ff6f6d1155bf99e3af45f90ee7bd48995d098681dda81db6da0f7635e504f163a6b95b6b249b403fd0c4177e5268622819c802b28ddec3e6234ab202412795f5a9778a0b42edd12b4ec7274ef0d7543b4322d9a05d4f5078569f7ed929bd6380f336d668332115da065d76ad86", 16).unwrap();

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

        let verifies = proof.verify(&encrypted1, &public_key, &unique_id, true);
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

        let verifies = proof.verify(&encrypted0, &public_key, &unique_id, false);
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

        let verifies = proof.verify(&encrypted1, &public_key, &unique_id, false);
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

        let verifies = proof.verify(&encrypted1, &public_key, &unique_id, false);
        assert!(verifies);
    }
}

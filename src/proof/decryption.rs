use num_bigint::BigInt;

use crate::elgamal::{Cipher, ElGamalParameters};
use crate::hash::hash_args;

#[derive(Default, Debug)]
pub struct DecryptionProof {
    pub d: BigInt,
    pub u: BigInt,
    pub v: BigInt,
    pub s: BigInt,
}

impl DecryptionProof {
    pub fn new(
        cipher: &Cipher,
        public_key: &BigInt,
        private_key: &BigInt,
        params: &ElGamalParameters,
        nonce: &BigInt,
    ) -> Self {
        let u = cipher.0.modpow(&nonce, &params.p);
        let v = params.g.modpow(&nonce, &params.p);

        let challenge = hash_args(vec![&public_key, &cipher.0, &cipher.1, &u, &v]).0;

        let s = (nonce + challenge * private_key) % params.q();
        let d = cipher.0.modpow(&private_key, &params.p);

        DecryptionProof { d, u, v, s }
    }

    pub fn verify(&self, cipher: &Cipher, public_key: &BigInt, params: &ElGamalParameters) -> bool {
        let challenge = hash_args(vec![&public_key, &cipher.0, &cipher.1, &self.u, &self.v]).0;

        let lhs = cipher.0.modpow(&self.s, &params.p);
        let rhs = &self.u * &self.d.modpow(&challenge, &params.p) % &params.p;
        let first_condition = lhs == rhs;
        assert!(first_condition, "1st condition failed");

        let lhs = params.g.modpow(&self.s, &params.p);
        let rhs = &self.v * public_key.modpow(&challenge, &params.p) % &params.p;
        let second_condition = lhs == rhs;
        assert!(second_condition, "2nd condition failed");

        first_condition && second_condition
    }
}

impl From<(&BigInt, &BigInt, &BigInt, &BigInt)> for DecryptionProof {
    fn from(tuple: (&BigInt, &BigInt, &BigInt, &BigInt)) -> Self {
        DecryptionProof {
            d: tuple.0.clone(),
            u: tuple.1.clone(),
            v: tuple.2.clone(),
            s: tuple.3.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use num_traits::Num;

    use crate::elgamal::{Cipher, ElGamal, ElGamalParameters, ElGamalPrivateKey, ElGamalPublicKey};
    use crate::proof::decryption::DecryptionProof;

    #[test]
    fn generate_and_verify_proof() {
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = BigInt::from_str_radix("2", 16).unwrap();

        let x1 = BigInt::from_str_radix("5f3a63e3b6e8c8a7063dc9d5eedd05eeeafd5b4881405cab5956030b135d633231265355ee149b4a6f383b8cb7b6b0c82fcb4981a1a4f186e2b8223851638f1a7c07a3d827608a476a0b3be0cdaf1dd8772b4215c6e90854671e55b0b89301065dfe81836cf303fa318a8b4b04e4596e9bdbb476eed488ee89079e2dcc146badddc08f04726a2da38c273eefbb90d487e36c9b4fcd56d289e54b868dc82b67656ac1f0112125e752fce353c2b5f743f54fff052d7a5fdde32065f53b6603c1013939936f67753cb5b0bd3a502ba8867b9b8b20ad4f186028d4a5e53eab7efcf61a08f8bfa39b692d1a1fe3e10e1e43e1f59f75bd562089099dc33da616f2ed", 16).unwrap();
        let x2 = BigInt::from_str_radix("92c38f9e7174f2d3b597b2a3b0b1d5c5e8fbb70de8d810c73e79d7abf469cfc139efbace7a5743029bfdb972140424a725f26a7a7f252e927150998b54f03813ee47a537a8856028831507a806575dac03e0a15b0f4e66e9a77cba4da68e55363927db3384140d8416e7cb238c8561833efb483e4e65f17e81537a5ccc11c629fddc2948b45ce1e17786c5293d8b751bfd30e13c0c939e3bfce9ec33da6e4ee866daec5e6d7a051434b93a0b05f99a4957fbbb236e1133f549c35258b433bd193cd1db55c6720e34b3578b092dac542754712332fbd8c9f2c548e0ec095b0d5d5f044dea99c398f1139a678e33e71d4101a1af15405e7d049c2801a75a1aa0", 16).unwrap();

        let params = ElGamalParameters { p, g };

        let private_key1 = ElGamalPrivateKey::new(&x1, params.clone());
        let public_key1 = ElGamalPublicKey::new(&private_key1);

        let private_key2 = ElGamalPrivateKey::new(&x2, params.clone());
        let public_key2 = ElGamalPublicKey::new(&private_key2);

        let public_key =
            ElGamalPublicKey::combine_multiple_vec(&vec![public_key1.clone(), public_key2.clone()]);
        let message = BigInt::from(12345);
        let nonce = BigInt::from(123);

        let encrypted = ElGamal::encrypt(&message, &nonce, &public_key);

        let proof1 = DecryptionProof::new(
            &encrypted,
            &public_key1.h,
            &private_key1.x,
            &params,
            &BigInt::from(3),
        );
        assert!(proof1.verify(&encrypted, &public_key1.h, &params));

        let proof2 = DecryptionProof::new(
            &encrypted,
            &public_key2.h,
            &private_key2.x,
            &params,
            &BigInt::from(5),
        );
        assert!(proof2.verify(&encrypted, &public_key2.h, &params));
    }

    #[test]
    fn generate_and_verify_proof_js_lib() {
        let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = BigInt::from_str_radix("2", 16).unwrap();

        let h1 = BigInt::from_str_radix("a284f0ce2a826cfb150fa8dd518d6946decae98aff496fb6a9c1d16dd762dd764e48de483a91d916d5e96e72d2d7f52c27fc54471f4aad1c90a2119e14f4fc9117f66a5525b292b71d7aa40ffe88b88cb154bea94717e33bb2e2bdc22b54c0a81f70ca3fe42fc8c901c825c6864eca5a29e256239406e666fc1f3b646cf08675d8ec1a15aaa41d66bd2606ae8b4081482dd031987e00013f981e6bc070b91423d5fb273eab4722bcacba29583bdb5ebb455a07ec1fa219fcaf56a63faa905294c325e4c121c57a0e5b7a20678a9932862873d714e650cf579bf9b036d8ce0361d3736a324da05ba004749180c996415b812717a481e087dbfd525e201be25d5", 16).unwrap();
        let h2 = BigInt::from_str_radix("c14d43cc72f6c5784275969d3dae8f33c4631fbdb7d3faa90e1fe846fbb4a69d756037b2fec40af2633797ec455bb167a05d8f145e9f2542d80ae45eb76e7a7b6984f3cbd92afda680ab5c57b2a9e83104ca60cbfe1a5111a9959326a4762a63587338cc6123ccace285bccaf92bf23e34b737591795cf871d9d4698cfc0e1e877bec8bb920941600092928f7210a9c8e164281b6e96c3c525676cb80874f06c682acc8465e475b46ff722babe5ff01c6490cc899ef799bbfe6a11e807826b714f7b8fe56b78fb58a89fafbae638e529090d5ee34491ef0bb3e65469aaf7de46cc1389840b77781914b2c9cde4b4f7e6694f9a64552222fd39bb048dff86040a", 16).unwrap();
        let h = BigInt::from_str_radix("cb19dce2bcaebc83f73723b77d5644bffc9b2877dd31646d6f838032cf93c8eb5f5d1fe98f6230a1ff0d62a1b988552e62bc7c634f4895d81ff72ffd753c553766468157ffd812b7ca65ad043498eb0b1329ab90fc4be1fba728ed523ece473e58ce5c7e17fded86d9a659ac5a5b674f2bdb09acdd4737a3e9f4e394cf69b1ca2917d71c165fdfeb3bba6bad183156dae5bca1c383e4315ec6e96fd6fe466d444d01511d6eda84c6179d1ec9c5ff9ff9fe45ae784a51e87d6aa8c02140c310aa69548063fdca74d85cf3b6a69fcb01946d03ca6c46aff782f7765134e73811ef285c73266a1ca974ad01cc69dc3d79dd764ddf3419b05614306580a2acae00b2", 16).unwrap();

        let x1 = BigInt::from_str_radix("5f3a63e3b6e8c8a7063dc9d5eedd05eeeafd5b4881405cab5956030b135d633231265355ee149b4a6f383b8cb7b6b0c82fcb4981a1a4f186e2b8223851638f1a7c07a3d827608a476a0b3be0cdaf1dd8772b4215c6e90854671e55b0b89301065dfe81836cf303fa318a8b4b04e4596e9bdbb476eed488ee89079e2dcc146badddc08f04726a2da38c273eefbb90d487e36c9b4fcd56d289e54b868dc82b67656ac1f0112125e752fce353c2b5f743f54fff052d7a5fdde32065f53b6603c1013939936f67753cb5b0bd3a502ba8867b9b8b20ad4f186028d4a5e53eab7efcf61a08f8bfa39b692d1a1fe3e10e1e43e1f59f75bd562089099dc33da616f2ed", 16).unwrap();
        let x2 = BigInt::from_str_radix("92c38f9e7174f2d3b597b2a3b0b1d5c5e8fbb70de8d810c73e79d7abf469cfc139efbace7a5743029bfdb972140424a725f26a7a7f252e927150998b54f03813ee47a537a8856028831507a806575dac03e0a15b0f4e66e9a77cba4da68e55363927db3384140d8416e7cb238c8561833efb483e4e65f17e81537a5ccc11c629fddc2948b45ce1e17786c5293d8b751bfd30e13c0c939e3bfce9ec33da6e4ee866daec5e6d7a051434b93a0b05f99a4957fbbb236e1133f549c35258b433bd193cd1db55c6720e34b3578b092dac542754712332fbd8c9f2c548e0ec095b0d5d5f044dea99c398f1139a678e33e71d4101a1af15405e7d049c2801a75a1aa0", 16).unwrap();

        let params = ElGamalParameters { p, g };

        let private_key1 = ElGamalPrivateKey::new(&x1, params.clone());
        let public_key1 = ElGamalPublicKey::new(&private_key1);
        assert_eq!(public_key1.h, h1);

        let private_key2 = ElGamalPrivateKey::new(&x2, params.clone());
        let public_key2 = ElGamalPublicKey::new(&private_key2);
        assert_eq!(public_key2.h, h2);

        assert_eq!(
            h,
            ElGamalPublicKey::combine_multiple_vec(&vec![public_key1.clone(), public_key2.clone()])
                .h
        );

        let proof1 = DecryptionProof {
            d: BigInt::from_str_radix("fd9bf8617c4fda9cf19cb329ca0debfe73de6e3d0ef4cacafc923b423e1ec1e86c4a7bd743f4f53d3ad518c03ff3cb93d20f42c0cea40d7d4d8db1010913b308ce89c4d2a555ff4b53677bd727f9ed9ca847f3eb8a3c5866d813abfe5f32e88cac5caa49f79e48cba1f8027089424c8ef87b9ac426d33c9272db3e67cae2a16a37f13941a89e899b0a72d93c2c177310d41f74a7b46497bbe04f6210ae9ceb09d204e484aece82d6a5395fe8281c2fe18ee8f1c5ce9132f44375377c91d1b6a8e03b2ce89c1fdbeb64d70f3a4d4f8d08ccc4aa6297080b1c64934772394a6f68da18a2e249a864ae85fd0892b0a620e5b27fe23f1fb65fbd719ded11ba59277", 16).unwrap(),
            u: BigInt::from_str_radix("adccbcf68e80600997deaf8f3489c74a6f9f6ccbe151f39c6602dd691806798219931f85fb3a2da5a843afeee547ebc7ef961dc511c7a8eecd54d71bd4f8b1526664d8785ac74779ac27660d1bfcb9a568f8fc30e46edba64e7071620c7d8f47557ad0915e912ec4976d6c3575183dfad2325c49e4742e2e4b97545dd2479da91b9757bf731ec1547602b70ff84b4d9d98e36228bfee4f07c232ce1b06d959b94729ec3aa54a7049823593113dc3abfc48471c33640e100c760c02207893f02216c9649c91224bf53fe6de821c4113d99256df6ed81e1f97b800dee0b384c28feb41df6bc49161ffc3c3a707214f5fd2c27d454cc53e2673b5caa81a99a6c21d", 16).unwrap(),
            v: BigInt::from_str_radix("15cb680fbc1d9ef1e15d78803683246b8f0fbae77b10172063038a48856d1c33cfe198b59e3fbf3fa1e391fc8a481d718990d2f3f2644a608eb9fb115559799cf419a4711287ed6fb433fae5595fc8fb213026901f4f9b08fdc35f1bb8a560bd14416e8b1cd6578c825735b0b551b1cc1b3b8dd75615a1ea1b3d9c2ec76fb1745c3851958522c4a61fe77ac85d777c02c7de76443afeba4f70307b277e41d35e4468462ba01c68ed6f7e540057db7ed5e1b7fdb6780772bfd94a31272e59ff4b2506569b66172a6f418e51e2620201df9bfdb164b967806ee05052a3ae2064ad23f8cf8d918f1684d4782fec10c0ff24aafb3cde7c870a9e8d409321778c954c", 16).unwrap(),
            s: BigInt::from_str_radix("71df44d88353c7dce12eb08cc0d031e0d59da58941ea463c037f54b658384f7b7baea9f22af4bdeca67575720e5f4adb715e699e4191e2dd12783dbb4c9654467f4ab7c70c19a315ac2cd6747c9c2b489aee938e34ec8f6e12a058179c991cd7ca261883f5ed436cd2102fe46e60fba964b5d6120163b80e3d3dee3d6d74dd8901a074101a6dd24e5b478820b8dbe111b485815170430c13ffeffdc49d3c5d9481cf3f7a0ce3a0eee73dd4a55bd6282ddbebe15171ffece4c5d8fbcab83e7d3d950c57607e91a7e28a04e1b1647faebecebee39fe47e9bb748ee8fc84fe85b8b0504d799385e87dcb6265055f33186920e4219701842f8702a374e3cd8726f0b", 16).unwrap(),
        };

        let proof2 = DecryptionProof {
            d: BigInt::from_str_radix("5aa56fc93b85d5fdefc28063a64ebb1c0fd92e92c8d12a8ea7af7683400a5af5d76548a04886f4c2470316d0d18e499f4f610d9916cf17281438951ed9228dbe7fe795dae3d9fc584fe1ac115a5de18ce7b7d07b9500a81be2a3570a3d38b5d3c8ccb53a16e3a966a0f82d69ae3d88e19e84984cebf0cc931a663538758cc3ba26fd87d4c362a8b66f4f0286d267f9e109c1f1cff2b003fb1df8b216cb14d7de76d3568c905b8a55eee857bf41cd66ec813cce51c0026fb1af22d8d19c28feb683dfc338ba1cd21c0a5f2fb69032c32064158a04d37e8c7a5052689167930fd073b956990796165d2af3e310a4f068cf3c260fd17a2b2c6c159985717568ac6c", 16).unwrap(),
            u: BigInt::from_str_radix("66378fdc4f7adb593b864b6c862db9f7de88c4f79f9e8ea62735c465c6c3891608d103f0f3d62b109f5aafa242b4b24efd29fee4d9647f12f3b0210648c1a041490e539ba34091d33712a89d40bab3ecb0149d9ffe9ace7d811da79df935db7abcfcbaf5b94f79cd1116103adc34498293b9348f818aed0b40bce00b98c9a95751a35a11921f343310e0506c6f3595a9c34bd09b4fce6cb904d2b8f8728ac7aad67355595fe826ac18d2dafbf44488dd88ee3f19c6cb8bde8b7b254b3f7b08751edd224bc1b7ac6e7ddbc5d7709d7fcac86a930f0f605b80d62ab4d0bd9971922faa5b2f60ee0b90c107989ffb770d80983b362a7d5a3ec3f108f2fa327a166", 16).unwrap(),
            v: BigInt::from_str_radix("b7239bc12fa27fa9dd3b08137b627a12ec0b297bf5de71cce575957c241a0c2a89243189a6a8dee747734c2399db3173f0b5b737eb3dd80ef54b403ae2ac61c9c3ce194785cf92d63521a3ca18a7f980b73fb84fdb678e26c421501be00e9fa3189283a7f3a1e3e69f3fb43efca4b8d1072dbc886272e5679ec116e143875ca2b53cc737cc2779e34c91c9af4723bc8e0a95b8a5ddc9fef7944deb833bfc26783e816a1d3b4d8750b65fa20ebad0fb4747874066f7cc2651e8493784dc7ebffe003f13fe557eea969010277ea385e7a9fb255240cd7ca1e47941ed129383aa7ae0375c773c98b87db6e2bf5744c8d4b831cfc63bc1c068d5d1b0d6d15d8fa973", 16).unwrap(),
            s: BigInt::from_str_radix("6a94d4ddafb9d83b64db808d7d0e2d2b242c53a1ec96e89d0940c2df8fcc357af5149f93214d81b8fcfe969c0174af59d0fccecacc76de983ab5c7e1da85d89ef0341a465d03dad65a663e9ca73ceea1e7ff5adc0db9de15b47b1146e38a8992551e17e0c5b4c381c1c4d7791f34605b8f8baf052aa3981c3b0938ad6925e9ea7ebd5027a737f357a3e838bc13839f9b91c29a7ebc55d62a34c1d0a49b73b030ccbb0c5ca836db014cd315b36014181950197a0f88e8525a440c1ef7c54a05c2d4859f333d92571ff1bef2fb868273aa263456c730d2d742c16439b00d05766512eca194e973a1af31f2d23b8b46bc8e2bd5c78e271fde137536911ce50c9ff8", 16).unwrap(),
        };

        let cipher: Cipher = Cipher(
            BigInt::from_str_radix("2e642106f424b8641da27e79e5ccfd8234d0061f5590af6281c39409492cf58402592ec7b417d8ba5e2851ebdff5237f063a7c17ca7185e0b5cc2b31c153921a8c3b7a709d26beba11fff4ed31f396197a251d12dc4e40b602f1f4ad6d24dc4c33ae547e158261385c968540663d49d2c816312ece11c09f04b03dd5014583895434b21b7a566c4539c865d99284cf17ed407c25029b48cb288ad678477dbe133ebec97c5855ba17a80d45c7dfe8ec7ee56a25a6c83f474ce839437142c577963e07c18c60879cb1790adbd6de3c989a0aac3912ea888c4c1585baf72457a2a305c52dca3f9fd538e0f45c45e4ffac974554dc20dc62d2f2190180f89ca32982", 16).unwrap(),
            BigInt::from_str_radix("6949c55fc8251110c6757b5dcde3746fad7c8bd47f09c726c0cc137de86c78fd47c08023e37646866ef4a034b9b090cfb06cda6570faee63ae93c2c2030f028b34bee685b9aac2d01c01b3ab58b7b9969225afbf6b9b5e4cac94e53b08f260add28b4da8bbf23a6935bbbb3f32bda610ba30631c361bc1fdceeb244f7d01abc665df3480e03c4e638aefe9f73c3dd44e7b0983b06c9fa8fb6a131429680b367c39d3c727de2b488c5acfc2cee53e6f4cba907133d71b9050363e66466a0c1a0ed94c78da117a6d43ef9165ef849ef8cb1d17fc7dfb93fe6b58cf9026f68ddabf9a0fd5899d3d3b67a225cbf889d7c997c240f3b2464b4f4fdb566f4a124f82eb", 16).unwrap(),
        );

        assert!(proof1.verify(&cipher, &public_key1.h, &params));
        assert!(proof2.verify(&cipher, &public_key2.h, &params));
    }
}

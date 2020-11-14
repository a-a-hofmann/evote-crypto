use core::iter;

use criterion::measurement::WallTime;
use criterion::{
    criterion_group, criterion_main, AxisScale, BenchmarkGroup, BenchmarkId, Criterion,
    PlotConfiguration, SamplingMode, Throughput,
};
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use rayon::prelude::*;

use crypto::blind::{verify_signature, RSAPublicComponent};
use crypto::elgamal::{Cipher, ElGamal, ElGamalParameters, ElGamalPrivateKey, ElGamalPublicKey};
use crypto::proof::ballot::BallotProof;

fn crypto_material() -> (
    ElGamalParameters,
    ElGamalPrivateKey,
    ElGamalPublicKey,
    Cipher,
    Cipher,
) {
    let x = BigInt::from_str_radix("c308aea0cd4859a06964f3aef8193705668887e889b259dcb3475cf793c3ede229ebef203716f56d5aa46f8ddf601da5d34468a1e006b61fd412d56dc41ef01e5144d150c62e3d51b6824ed7514d1a36bce7abbea0501a093f2348d6e6bdfebb0dcebc789ca352b9874fd1519deb85e13af2879394e5ac62e252cac530b6b98da77d7b64c56156ea77f22416815f44e90a879e020ed543f63c03323f2e42d3d14e1c01b7e0c1bad4e289f274ee73f253622c671c0a02688f3cf98607236a99d1f83bde87c4a53ed6910d21501c926d8e492406aa42ef6e0559dc49ca1cd41821f80bcea45d52306c4833a2fd0a73606b714b5d20c4fbaa43d1c94c09fa614a", 16).unwrap();
    let h = BigInt::from_str_radix("61cb62ec3387adbdf2f01c6169f6493f86890c6779f92f375426ea69c7f7e79baef2ad7319441342690e4dbb428634270a7081571717fc8d997f1c4c7c92f84566c53c123092e4ab1e9df18ddbb9e5f98ca386d8b19d6e65c116ad12bfa07506f57d1890d7a08f8fb1fc0f354d4f8cebee9fc81c06502c8fac80e67fa00fffe14ee3b311a81a20217809e56831a1050e3a61724ecf8682625452ebc290d1d4aca22c29380039e6181bc0e2df19b9a8f76bd6e3a0ea5e089b9182840b661efb9b1ce3ca3f39be2025dcbce2d3f2e56a97f637c79bca16da9e4edb6ebb02564794465cf15d09cdea5f24055016e8bf3d9652eea75df5a4d49e62819e7f2da70f6b", 16).unwrap();
    let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
    let g = BigInt::from(2);
    let params = ElGamalParameters { p, g };
    let private_key = ElGamalPrivateKey {
        x,
        params: params.clone(),
    };
    let public_key = ElGamalPublicKey {
        h: h.clone(),
        params: params.clone(),
    };
    assert_eq!(private_key.extract_public_key().h, h.clone());

    let nonce0 = BigInt::from_str_radix("fa08aea0cd4859a06964f3aef8193705668887e889b259dcb3475cf793c3ede229ebef203716f56d5aa46f8ddf601da5d34468a1e006b61fd412d56dc41ef01e5144d150c62e3d51b6824ed7514d1a36bce7abbea0501a093f2348d6e6bdfebb0dcebc789ca352b9874fd1519deb85e13af2879394e5ac62e252cac530b6b98da77d7b64c56156ea77f22416815f44e90a879e020ed543f63c03323f2e42d3d14e1c01b7e0c1bad4e289f274ee73f253622c", 16).unwrap();
    let nonce1 = BigInt::from_str_radix("dea08aea0cd4859a06964f3aef8193705668887e889b259dcb3475cf793c3ede229ebef203716f56d5aa46f8ddf601da5d34468a1e006b61fd412d56dc41ef01e5144d150c62e3d51b6824ed7514d1a36bce7abbea0501a093f2348d6e6bdfebb0dcebc789ca352b9874fd1519deb85e13af2879394e5ac62e252cac530b6b98da77d7b64c56156ea77f22416815f44e90a879e020ed543f63c03323f2e42d3d14e1c01b7e0c1bad4e289f274ee73f253622c", 16).unwrap();
    let vote0 = BigInt::from(0);
    let vote1 = BigInt::from(1);

    let ciphertext0 = ElGamal::encrypt(&vote0, &nonce0, &public_key);
    let ciphertext1 = ElGamal::encrypt(&vote1, &nonce1, &public_key);

    (params, private_key, public_key, ciphertext0, ciphertext1)
}

fn prepare_benchmark<'a>(
    c: &'a mut Criterion,
    group_name: &str,
    sampling_mode: SamplingMode,
    axis_scale: AxisScale,
) -> BenchmarkGroup<'a, WallTime> {
    let plotting_config = PlotConfiguration::default().summary_scale(axis_scale);
    let mut group = c.benchmark_group(group_name);
    group
        .sampling_mode(sampling_mode)
        .plot_config(plotting_config);
    group
}

fn bench_homomorphic_sum(c: &mut Criterion) {
    let (params, _, _, ciphertext0, ciphertext1) = crypto_material();
    let elements_count = [1000, 10_000, 100_000, 1_000_000];

    let mut group = prepare_benchmark(
        c,
        "Homomorphic sum",
        SamplingMode::Auto,
        AxisScale::Logarithmic,
    );
    group.sampling_mode(SamplingMode::Auto);

    for count in elements_count.iter() {
        let ciphers0: Vec<Cipher> = iter::repeat(ciphertext0.clone())
            .take((count / 2) as usize)
            .collect::<Vec<_>>();
        let ciphers1: Vec<Cipher> = iter::repeat(ciphertext1.clone())
            .take((count / 2) as usize)
            .collect::<Vec<_>>();
        let ciphers: Vec<Cipher> = [ciphers0, ciphers1].concat();
        assert_eq!(ciphers[0], ciphertext0);
        assert_eq!(ciphers[(count - 1) as usize], ciphertext1);
        assert_eq!(ciphers.len(), *count as usize);

        println!("Adding up {} votes", ciphers.len());
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &ciphers,
            |b, ciphers| {
                b.iter(|| {
                    let _sum = ElGamal::add_parallel(ciphers.clone(), &params);
                })
            },
        );
    }
    group.finish();
}

fn bench_decrypt_many_votes(c: &mut Criterion) {
    let (params, private_key, _, ciphertext0, ciphertext1) = crypto_material();
    let elements_count = [1000, 10_000, 100_000, 1_000_000];

    let mut group = prepare_benchmark(c, "Decryption", SamplingMode::Flat, AxisScale::Logarithmic);

    for count in elements_count.iter() {
        let ciphers0: Vec<Cipher> = iter::repeat(ciphertext0.clone())
            .take((count / 2) as usize)
            .collect::<Vec<_>>();
        let ciphers1: Vec<Cipher> = iter::repeat(ciphertext1.clone())
            .take((count / 2) as usize)
            .collect::<Vec<_>>();
        let ciphers: Vec<Cipher> = [ciphers0, ciphers1].concat();
        assert_eq!(ciphers[0], ciphertext0);
        assert_eq!(ciphers[(count - 1) as usize], ciphertext1);
        assert_eq!(ciphers.len(), *count as usize);

        println!("Adding up {} votes", ciphers.len());
        let sum = ElGamal::add_parallel(ciphers.clone(), &params);
        group.throughput(Throughput::Elements(*count as u64));
        println!("Decrypting sum of {} votes", ciphers.len());
        group.sample_size(10).bench_with_input(
            BenchmarkId::from_parameter(count),
            &sum,
            |b, sum| {
                b.iter(|| {
                    let _plaintext = ElGamal::decrypt_with_heuristic(&sum, &private_key, *count);
                })
            },
        );
    }
    group.finish();
}

fn bench_voter_registration(c: &mut Criterion) {
    let exponent = BigUint::from_str_radix("10001", 16).unwrap();
    let modulus = BigUint::from_str_radix("e97a728532da5af885d0fbfc2dbe97854eb7765e209ed8c426092c8c9f22a60bf29018a8c8a86f7957e5dba77f95bfcee901fc8d5a633b60d0a6bb7bc7f6bb63edf229872d223d87b133875161c2502c099a2731a6567346e339eb5fa73460516784eaa1c96eb37270744a152c8908a1cc73aab10608123861b8a466abd5f6f230a11d935675659bee231c61f763f13b192181d40aba657da2693b07af818e472919dbfc756fc2eb59f4e6cc077e6cd2621f3688e4af6a4567d2b9cf55261a8b92733decbbd48ea9a1603c7dd9ed89244bfc54e1007bb429392f9577615dad735b89e3b3f0dbd5d30becbc0ceedd4d1071dba4f141f6961f14cbc671c7babbdd", 16).unwrap();
    let signature = BigUint::from_str_radix("d53aeb427e94c03ddd7eb38454e3d32ef04abf0a154bd819e4b993e9f648c755ea921cc2070bf67387b089946f3814c1e13436dd52885b697854545e5d3d9442cb74f9be6393f6def6513be89362e7e08f8fbbd0d9c2932612f16d2b1275dea725d33125a6859830852866b35e0992fe1450f59d8fb2f06b16f1f781285fa46eac566435057cbacd0ebf8e53822f5f166cb6061437fa7442351645fe1e46ec7abe71a83048e5da649654337699d0882509d154448c07db652575c8f5005aa031a57262df9c54bc453f2534e6d93277e3f269af4f36a3a60414eef83f973a8b630073d2e827e8e7c0214dbc038926964e40c4fc22f3081072c81bfff53da69352", 16).unwrap();
    let rsa_component = RSAPublicComponent { exponent, modulus };

    let address = b"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_vec();
    let result = verify_signature(address.clone(), &signature, &rsa_component);
    assert_eq!(result, true);

    let n = [1000, 10_000, 100_000, 1_000_000];

    let mut group = prepare_benchmark(
        c,
        "Voter registration (RSA Blind signatures)",
        SamplingMode::Flat,
        AxisScale::Logarithmic,
    );

    for count in n.iter() {
        let signatures: Vec<BigUint> = iter::repeat(signature.clone())
            .take(*count)
            .collect::<Vec<_>>();

        println!(
            "Verifying {} signatures. Count {}",
            signatures.len(),
            *count
        );

        group.throughput(Throughput::Elements(*count as u64));
        group.sample_size(10).bench_with_input(
            BenchmarkId::from_parameter(count),
            &signatures,
            |b, signatures| {
                b.iter(|| {
                    signatures.par_iter().for_each(|signature| {
                        verify_signature(address.clone(), &signature, &rsa_component);
                    })
                })
            },
        );
    }
    group.finish();
}

fn bench_ballot_proofs(c: &mut Criterion) {
    let unique_id = BigInt::from_str_radix(
        "f6357c14c3d573f308c3b6cd028d284a7cc332ce96ab2c2836a56cb3a0f91600",
        16,
    )
    .unwrap();
    let x = BigInt::from_str_radix("75aa20443640a0bfe436f46e20db97aa698d1632fbfe989f3b01e32ca74c753bdbe0946483aa65e39a5367330df1622500b9bf65cc65e09e29b283c4cc85ee81f6af783f622fb111a4beecd47df7c17918a38a8d4d50349047186f394e8a7fcc000777f216426cbd68a0284a286dca11e33717e54c343ab9464aa2a9d8a35bd744c9262c17dd62f8e2ba2886c890790f24f141ae3290c1d2f9edf2d70bdf3c4780d75446560059f74d67a32ee8cadae0335d66e842f53713cd4f37a728ff1da454861ee53b88c9b8f181ba85db54810eeae129a26f7f80ca077abcc7ba8b31a4084f5c9c0bfdf3f9aaf35775413fe70a07d7c7e441a45b1d0b4ae44837a5d7", 16).unwrap();
    let h = BigInt::from_str_radix("d69284b6368bc387f82cabc5e5a4a49c0a0a05f1108b26615df612ffd14f865b8a93a943f5d2d38a63395422cdc8f3e40ac13e8e5ccdb90772f93a925caf492faa4d8015b80627716936ddae4834a91b8086c5a5826a78534ca1c325233c5f51d90bdb05c322e9381b141c85b43d0a2e3edf9b4a99207cbd6597530c6e1afa907a829153f9f4da3a8c362efcbfb273d90653a6ec31fb076b439920509778c2df78030755369e19bde4cb723e1bb5f0831dcb25507ceb8004bd1a8b1e5cb6b4709e85299ef5b6de87cbafd267f9e337a8d2fbdfc9fa366459753a574d213bd2e2fb17d8680801174c02d436ed9d8a353d7381457647a2a03682b0958931acc8a1", 16).unwrap();
    let p = BigInt::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
    let g = BigInt::from(2);
    let params = ElGamalParameters { p, g };

    let _private_key = ElGamalPrivateKey {
        x,
        params: params.clone(),
    };
    let public_key = ElGamalPublicKey {
        h,
        params: params.clone(),
    };
    let n = [1000, 10_000, 100_000, 1_000_000];

    let nonce = BigInt::from_str_radix("7a2999ab10808130a30c33c8e7b023ea91875bbca501fe96922f006634e44d61e418eccda3e1b028e118a685e7d300a432dd529245110d39f982f78b63f3e519d2629fc0ec2e4ffec8e97397b4a3741c26fd26c32908320fc491bd45ee7ddc5221d27b7a5f5518dafad0517d8486a9d76963c31178231399ab5e6dc2b2b06885a8237eefead8686845b29c87d938e1c1ad03acf51873ff91a49568f334f0d8dd68bc77f85a642b3aafa35f860ad110c9906c0c66c68543fbee4d73fc5e0f55f129687548dfd9191a4c9e66d89d1047d70937853a7f95c4f8435b837ad9776af7c32c4b75b54ebe7af498ba97f81edd3270e567199b4426f3707fd86438be4c", 16).unwrap();
    let vote0 = BigInt::from(0);
    let vote1 = BigInt::from(1);
    let ciphertext0 = ElGamal::encrypt(&vote0, &nonce, &public_key);
    let ciphertext1 = ElGamal::encrypt(&vote1, &nonce, &public_key);

    let proof0 = BallotProof {
        a0: BigInt::from_str_radix("64732df64d071b5c69a516aac7ed4d0ba16cbbed63bbe6f94fa3957fddee6f13e0dbbf5424781eff53dbbb381257fb0f26f03eb394414c99db3840296c9892243d0f170b284e3c4930b888c0a9d92e47b6f01429ec5a30df1a892454dafa3d6b4962966308021114f8fc2a0de9677a6f97b2ad113bc6970b7b11a7e2b9d5edcb43c8d5f98c0666d0fa5a5e551fc26adf3e548cb38ebeacbaf5c9f1b8872ea51c81cd09edd4e9c038783de21cd93bbdb1d52d8c699d036fb1168dfa1b0e626946fec06a02b49cff00072725e67a68b029c0796a7d80f2daa6c2ddf1a0ef9af2bd7f6af63c810940ee366ef5cdc25ef5a36d1a524a14f8f6813861381af67c4fc4", 16).unwrap(),
        a1: BigInt::from_str_radix("add021419d2d769cf4bf1c1a027c4c89b823c6f26353db3294bc645d2d095662dc4fe8f078099d6abe21869531d39ad891c7e8cb251b4f8ea62a9971ba9e5f3c2a5d496de67e8d4e8fe57832c2ad6f9e7ecaefb6acfbbda4519c8d6e53742a461dab9e4aff76cba15ac0481c15cfbf12d9d0eeaab208f0973b8ae7720f36888bd59b0e36a6b1d8380299474a14c3aaa0c243326ff0ff6aa999b047c3b1823e31bb984b5390609f6f072a7a5b407ba2992e3a1399581f42099ce973ab0c3426a7077c1297db2afd2f20881fc3520246007851f1d83fd54d33201290a1d58698fe99aa4da2288d94a8786fc926a4fc4493ba464e4a270f386729ddb0edb2bac075", 16).unwrap(),
        b0: BigInt::from_str_radix("7bfae96deb26928f9463000fe5c785618213833da9cdf026c2b5aee9dcf3c6872a0838d938686591a39e16c0dcd4b95177758eee05042b707060bb80e1e459a3c3de9594956f2be629a34f8a86844421c1683ee9625c5935488d95e2f0d751485cf3dab34aa3b3aca180a36702ed79738220f432a67483baa4428c7006d1c1778c9c3f80495e2d04e5ab1c35978d5aaa152650e2a3306ca32436720b01732fe265f3283cb6f55311ef7a2e78e9243a8331b059eba617678f652133b417b2004847535fffb996eacc45e5b20b596f58d5a1d729fafc3410319a414847d3613db4c04faf7b36a1fa729db17740e299a8aac64383a1f9b640468d7bece3982b65f9", 16).unwrap(),
        b1: BigInt::from_str_radix("13c72458dfa10017f94cb08cd113e73d71c1aa9db1d3d41ed855e29a4f1e66e7d639bac5fd03d807337266a6e94dc76cc5378acc47a068a45c49c4cb787b991c895cb1d09e74713e816ec543c565b48f2f85ee29ca02224b3814e291c17c20f01b887b189444235b97b1e9d3d4f9504fbdd53690b5d43ee72993cf02a45bfa31252f1288e7ab2d6dc347eca26d733bfaa476977e6946777cdd4834ba2a9279cb473292352d65a5f530f816b4c9b6b99c113bee157bab4862bfe56584cab9995486b1e88759bf5c053fea85a143463a1f68a4fabfe9cb1f0267177f72f5985d60b8b06ad15563d2acc0fa67ed046da3eb187681b3cf611c1d9039d8b7a06f9d74", 16).unwrap(),
        c0: BigInt::from_str_radix("cc", 16).unwrap(),
        c1: BigInt::from_str_radix("33", 16).unwrap(),
        r0: BigInt::from_str_radix("6182ed066e0d2a2bb52f2e20bc3dfbc71b35498c7358176301dfea371f7e4e71891f1d229a44835b9ac10f24cb48565f769e99845f88510832b64ce0dc15c468ed417c97297c41f70608b55e4874381fb2e057a00c4e01bb2691b3aca05c3ee02ae616dcdcaec38db6b2cd6fe8e04ad96962daf00d22c3ddc76bf10f44e6c869cdfb6ef11d91438e7505ae8f1c338d688fc76e43614938a6de03485275a93497f6b99b3be2ce2ad9075191c905786b620b7011bbd77c43bbd643576a1bf09cb91aa0edcf3994628a7991f5d02871e00bcdc0c44dacc7fa443b93056a0b2f13b094532dcc21d55a879ffa84382e3c980e9e3c8ff9467553694ec714354dbaf9c8", 16).unwrap(),
        r1: BigInt::from_str_radix("56c9c409345519399ef3c98da629db314f0e59c456f9f383ef5dfc300111237b371f7c3e3bed50e645fa5e7fc86d02f8525e2742dce8f5da7d4001ab85d2dcbb3623ce7c16c0c6afec3ae31a3f45b1705010bc563d98fdb219310599c9700e4fa87079607f866020d9988f229bb7337fc8ddf905b026cd267905ae7d1cd8f6b974950ce0443d8c8b74d2307cd66e4582e493e2fa0b93b92affbe68a396337214753dc22617a0db86b156ca607095de53b869a8e8121e3ad4bbfbd8ee3c586c9e1c12feefc08cbd7cbd4461ff7cd5b47a934a51c9d506e82118b3b64cd706e8724a6fec1a6070cc737eac8439c76f636adfae757f2aaeab8842809f31e47f0d", 16).unwrap(),
    };

    let proof1 = BallotProof {
        a0: BigInt::from_str_radix("74d012cb0bac2fd94e3601a94f5323de3f86610590ea857f9b18e84b2f98f428a45db728a465b567710fa86e47e8e0602c11e777ac801d1bffeaeaaccfbe55c0b8771e935137d0c2124b90a0210c77cc3c6b6db65767f55f3ec47e52f265232d2ab410cfb5bd2bea9230b05bdd4480505d3857e23e7a99b41dee014b5774600a9cf4e1fa9708ed7fe3e0e3c0712fe2f01638544df5c4590f825c035bab8c7930a9aa382a30d2949bb7a16000d77a632deb2184a3d3b8390e828cbbca2bba593e6d62297e7573429d3bc6f29bee1de666e5b14c6c271e620923a3ce2085320d2830ec6e0158b384e129fa26c346aea1b59971b7c22ba8b84a6819c79fd9395924", 16).unwrap(),
        a1: BigInt::from_str_radix("a53b8a17348a7ec512c9f3bc1bd6c1ebd3c177230e82d133dbd653377f3790d671fdee64bea8484e226239bc68550ba9dade4d002e8989414188cc6fe76eedc73a0395e7edcf3e40f8af4135c9d99aa22aa397605a5a6cc219a9a3f25843e1528d1a728cb82cc452222e742db375c113bcc6e336b1d27f49506eed864c759bd087b0ae86f601086d657f7c2f202ad51ef491f34424a6c32adfd1a1575edd747cef82b691bbe3280585e33a1d40e3fb3b34fb1f7c522f9f58578e37ee9f49f400b9841b041631f10d3ba030c84e88e4560a03deacb51f58aaa02718785399da54f5d6793bc029d9f5d51eaddf63c2e782c1c3ed0bd8de7d9df4cb92e4f0d1247f", 16).unwrap(),
        b0: BigInt::from_str_radix("8361e882f09febff526e6cadb0bbab8076f82f1094e2cb6e5132560188e269dc37d72093535a6c0457103650b56578d996b8d2dc846e011c66167f9431d0d3e62d218665f65d8df100e38d5f1dc2193f180e189e33b475e8beb1585890fccf721fd755a1a43d95aaf33763f98786ee1eadd18dcad5e41167030a562e1be2f8559be1ee5864c275ad99560c293c1df74e159fe8a6302ea458b16cda67984622148b7bedfb62e84629915f9a717e19a44e7221150c0b80a8a75b2ad3da32adb7442969ea61023ad0aee0156e83e23a673380ac9813b76abadf25cfacc0ed70dd4ba6b760049d5bab1c85adb582380981c4d9a5c6e31c3bd0038d5c5a8fce2d440e", 16).unwrap(),
        b1: BigInt::from_str_radix("f3e186df857296e2c812421b63ab5b986163a38f6b6c6ed6f33c5fd783789e4fe6d685db9154e4ec8bc6feb716af8672f0a053fc67af4c581157e6b62357255060d49932dd460039033097e7d094f439d299e6a791355c9bf163335d22129c3f106b4419dbaa30cdfdbe6a2d560e8238f65da400837cd37bcdb916061e64341cfc144f2683b7d62544b428ba163de9fcada93b076a990951a17580b7158dbb41894ae8a917edd62804089898a1014b2521883ccbb631d212b30f247dd52cfa34a11a7b8187cef6e0225cc90c30227ad13ba9b2a82ab22eb5ee88e22105eec53ea59c14207fdc321f60e04d83f538a18b52243a533524d33b54f7b6b0521ba018", 16).unwrap(),
        c0: BigInt::from_str_radix("4f", 16).unwrap(),
        c1: BigInt::from_str_radix("4b", 16).unwrap(),
        r0: BigInt::from_str_radix("5329856b0686d17961034a914411eef89748c9f03cbb53c8607c1e3910761ab8c022ee511b2479b093eeb70c41a0671f4987a5eb78675eb55821d8944f3d9f13770b7ca924547f8ec0fdfabac76542fa56b61d3112fa8b76507be9f303af81b31ab2887b64030b7ed446e27c6051f865fc5fe993843d9cba3024d7f13f426104faa921c85be2914c2930760cc70a23e45f2a1669189ca96353f127e8db946a96a574c6fb004f942528061545da6d2797a588db24db863f98de971fa1581142b73a11153aeb7f70c99d23fd41fcef11662f7cbaa4a5e5a8ca48616f5ef980c3c81d0a28525029c98925f483f21e2ac51fb224002af4cd919feb267003548d50", 16).unwrap(),
        r1: BigInt::from_str_radix("24ca13fc01c2687e0c3265a8c630b9b984246449401d8a96c9ce9ba30a9a75fe6bd9ffd979b99a24678419d2f2877c7679ea9f70544c6f733ac9b680c00d4a3919c7cab36714fb12536215b52671c0b529a19adb238d5ad5ccb6507ea0202983b5e51ba82f03609bc3351e2e9592f9a2899b2b8b9bc132aa2a317a6bee254d88bff765943b30d872f4e03f9dd0dafad802690c3bc71e40f4108d9f6c2899054a6a6b163ae245b35414c08870cbec518ff4067efa6c8541c9013792fc26156cf1b487d6a00a65be7e5fcb15c59243699457e25456f3c4afeea4813b1ddeb7ffeadd87a573dca2a44e1d02721cdec17e6f6540a577e8480a6c429162b4ab095f7d", 16).unwrap(),
    };

    assert!(proof0.verify(&ciphertext0, &public_key, &unique_id, true));
    assert!(proof1.verify(&ciphertext1, &public_key, &unique_id, true));

    let mut group = prepare_benchmark(
        c,
        "Ballot proof verification",
        SamplingMode::Flat,
        AxisScale::Logarithmic,
    );

    for count in n.iter() {
        let proofs0: Vec<BallotProof> = iter::repeat(proof0.clone())
            .take(*count / 2)
            .collect::<Vec<_>>();
        let proofs1: Vec<BallotProof> = iter::repeat(proof1.clone())
            .take(*count / 2)
            .collect::<Vec<_>>();
        assert_eq!(proofs0[0], proof0);
        assert_eq!(proofs0.len(), *count / 2 as usize);
        assert_eq!(proofs1[0], proof1);
        assert_eq!(proofs1.len(), *count / 2 as usize);

        println!(
            "Verifying {} ballot proofs. Count {}",
            proofs0.len() + proofs1.len(),
            *count
        );
        group.throughput(Throughput::Elements(*count as u64));
        group.sample_size(10).bench_with_input(
            BenchmarkId::from_parameter(count),
            &(proofs0, proofs1),
            |b, (proofs0, proofs1)| {
                b.iter(|| {
                    proofs0.into_par_iter().for_each(|proof| {
                        proof.verify(&ciphertext0, &public_key, &unique_id, true);
                    });
                    proofs1.into_par_iter().for_each(|proof| {
                        proof.verify(&ciphertext1, &public_key, &unique_id, true);
                    });
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_homomorphic_sum,  bench_voter_registration, bench_decrypt_many_votes, bench_ballot_proofs);
criterion_main!(benches);

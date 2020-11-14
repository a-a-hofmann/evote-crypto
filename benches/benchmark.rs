use core::iter;

use criterion::measurement::WallTime;
use criterion::{
    criterion_group, criterion_main, AxisScale, BenchmarkGroup, BenchmarkId, Criterion,
    PlotConfiguration, SamplingMode, Throughput,
};
use num_bigint::BigInt;
use num_traits::Num;

use crypto::elgamal::{Cipher, ElGamal, ElGamalParameters, ElGamalPrivateKey, ElGamalPublicKey};

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
    let elements_count = [1000, 5000, 10_000, 50_000, 100_000, 500_000, 1_000_000];

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
    let elements_count = [1000, 5000, 10_000, 50_000, 100_000, 500_000, 1_000_000];

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

fn bench_votes_decryption(c: &mut Criterion) {
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
        h,
        params: params.clone(),
    };
    let n = [1000, 5000, 10_000, 50_000, 100_000, 500_000, 1_000_000];

    let nonce = BigInt::from_str_radix("fa08aea0cd4859a06964f3aef8193705668887e889b259dcb3475cf793c3ede229ebef203716f56d5aa46f8ddf601da5d34468a1e006b61fd412d56dc41ef01e5144d150c62e3d51b6824ed7514d1a36bce7abbea0501a093f2348d6e6bdfebb0dcebc789ca352b9874fd1519deb85e13af2879394e5ac62e252cac530b6b98da77d7b64c56156ea77f22416815f44e90a879e020ed543f63c03323f2e42d3d14e1c01b7e0c1bad4e289f274ee73f253622c", 16).unwrap();
    let vote0 = BigInt::from(0);
    let vote1 = BigInt::from(1);

    let ciphertext0 = ElGamal::encrypt(&vote0, &nonce, &public_key);
    let ciphertext1 = ElGamal::encrypt(&vote1, &nonce, &public_key);

    let mut group = prepare_benchmark(
        c,
        "Homomorphic sum and decryption",
        SamplingMode::Flat,
        AxisScale::Logarithmic,
    );

    for count in n.iter() {
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

        println!("Adding up {} votes, with count {}", ciphers.len(), count);
        group.throughput(Throughput::Elements(*count as u64));
        group.sample_size(10).bench_with_input(
            BenchmarkId::from_parameter(count),
            &ciphers,
            |b, ciphers| {
                b.iter(|| {
                    let sum = ElGamal::add_parallel(ciphers.clone(), &params);

                    let plaintext = ElGamal::decrypt_with_heuristic(&sum, &private_key, *count);

                    assert_eq!(plaintext, BigInt::from(count / 2));
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_homomorphic_sum, bench_decrypt_many_votes, bench_votes_decryption());
criterion_main!(benches);

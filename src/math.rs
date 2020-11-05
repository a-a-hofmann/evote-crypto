use num_bigint::BigInt;
use num_traits::{One, Zero};
use rayon::iter::IntoParallelIterator;
use rayon::prelude::*;

///
/// Compute division in a multiplicative finite field `p` of `a/b`.
/// This equates to `a * mod_inverse(b, p)`.
/// The `division` is modeled as a multiplication with the modular multiplicative inverse.
pub fn mod_div(a: &BigInt, b: &BigInt, m: &BigInt) -> Option<BigInt> {
    mod_inverse(b, m).map(|inverse| a * inverse % m)
}

///
/// # Modular Inverse
///
/// Calculates the modular inverse `a^-1 mod m`
///
/// ## Credits
/// Inspired by [simon-andrews/rust-modinverse](https://github.com/simon-andrews/rust-modinverse)
/// Found in [crypto-rs](https://github.com/provotum/crypto-rs/blob/master/src/arithmetic/mod_inverse.rs)
///
pub fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (g, x, _) = extended_gcd(a, m);
    if g != BigInt::one() {
        None
    } else {
        // actually use the modulus instead of the remainder
        // operator "%" which behaves differently for negative values
        // -> https://stackoverflow.com/questions/31210357/is-there-a-modulus-not-remainder-function-operation
        let modulus: BigInt = (x % m) + m;
        Some(modulus)
    }
}

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    assert!(a < b);
    if *a == BigInt::zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = extended_gcd(&(b % a), &a);
        (g, y - (b / a) * x.clone(), x)
    }
}

///
/// Solve dlog mod `modulus` by brute force:
/// Attempts to find a value `i` such that `target = generator^i % modulus`
///
pub fn brute_force_dlog(target: &BigInt, generator: &BigInt, modulus: &BigInt) -> BigInt {
    let mut i = BigInt::zero();

    while &generator.modpow(&i, &modulus) != target {
        i += 1;
    }
    i
}

///
/// Solve dlog mod `modulus` by brute force:
/// Attempts to find a value `i` such that `target = generator^i % modulus`
///
pub fn brute_force_dlog_with_heuristic(target: &BigInt, generator: &BigInt, modulus: &BigInt, upper_bound: u64) -> BigInt {
    let found = (0..upper_bound).into_par_iter()
        .find_first(|item| &generator.modpow(&BigInt::from(*item), &modulus) == target);

    BigInt::from(found.unwrap())
}

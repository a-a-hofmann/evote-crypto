use num_bigint::BigInt;
use num_traits::{One, Zero};

///
/// Compute division in a finite field `p` of `a/b`.
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
    let (g, x, _) = extended_gcd(a.clone(), m.clone());
    if g != BigInt::one() {
        None
    } else {
        // actually use the modulus instead of the remainder
        // operator "%" which behaves differently for negative values
        // -> https://stackoverflow.com/questions/31210357/is-there-a-modulus-not-remainder-function-operation
        let modulus: BigInt = (x % m.clone()) + m;
        Some(modulus)
    }
}

fn extended_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    assert!(a < b);
    if a == BigInt::zero() {
        (b, BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = extended_gcd(b.clone() % a.clone(), a.clone());
        (g, y - (b / a) * x.clone(), x)
    }
}

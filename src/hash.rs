use alloc::vec::Vec;

use blake2::Blake2b;
use digest::Digest;
use num_bigint::{BigInt, BigUint, Sign};
use sha2::Sha256;

pub fn hash_fixed(arg1: &BigInt, arg2: &BigInt, arg3: &BigInt) -> BigInt {
    let mut hasher = Blake2b::new();

    let arg1 = arg1.to_bytes_be().1;
    let arg2 = arg2.to_bytes_be().1;
    let arg3 = arg3.to_bytes_be().1;

    let concatenated = [&arg1[..], &arg2[..], &arg3[..]].concat();
    hasher.update(concatenated);

    let hash = &*hasher.finalize();
    BigInt::from_bytes_be(Sign::Plus, hash)
}

pub fn hash_args_variadic(args: &[&BigInt]) -> BigInt {
    hash_args(args.to_vec())
}

pub fn hash_args(args: Vec<&BigInt>) -> BigInt {
    let mut hasher = Blake2b::new();
    let mut buffer: Vec<u8> = vec![];

    for arg in args {
        let mut bytes = arg.to_bytes_be().1.clone();
        buffer.append(&mut bytes);
    }

    hasher.update(buffer);

    let hash = &*hasher.finalize();
    BigInt::from_bytes_be(Sign::Plus, hash)
}

/// Computes a sha256 of a message in bytes.
/// returns an unsigned big int.
pub fn hash_bytes(bytes: Vec<&Vec<u8>>) -> BigUint {
    let mut hasher = Sha256::new();
    let mut buffer: Vec<u8> = vec![];

    for arg in bytes {
        buffer.append(&mut arg.clone());
    }
    hasher.update(buffer);
    let hashed = &hasher.finalize()[..];
    BigUint::from_bytes_be(hashed)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use num_bigint::BigInt;

    use sha2::{Digest, Sha256};

    use crate::hash::{hash_args, hash_args_variadic, hash_fixed};

    #[test]
    fn sha256_test() {
        // create a Sha256 object
        let mut hasher = Sha256::new();

        // write input message
        hasher.update(b"Hello Chaum!");

        // read hash digest and consume hasher
        let result = hasher.finalize();

        assert_eq!(
            result[..],
            hex!("7d90a8d6e5be1edd85a966762aa9627f69eea0a1e3a45c2b7a722e76f115798b")[..]
        );
    }

    #[test]
    fn test_hashing() {
        let arg1 = BigInt::from(2);
        let arg2 = BigInt::from(3);
        let arg3 = BigInt::from(4);
        let hashed1 = hash_fixed(&arg1, &arg2, &arg3);
        let hashed2 = hash_args_variadic(&[&arg1, &arg2, &arg3]);
        let hashed3 = hash_args(vec![&arg1, &arg2, &arg3]);

        assert_eq!(hashed1, hashed2);
        assert_eq!(hashed1, hashed3);
    }
}

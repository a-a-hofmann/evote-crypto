use num_bigint::BigInt;
use num_traits::Num;

use crate::elgamal::{ElGamalParameters, ElGamalPrivateKey, ElGamalPublicKey};

pub fn create_crypto_material(
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

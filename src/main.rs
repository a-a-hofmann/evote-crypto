use crypto::rsa::*;
use num_bigint::BigInt;

fn main() {
    let (public_key, private_key) = RSA::new_key_pair();

    let original_message = BigInt::from(65);
    let cipher_text = RSA::encrypt(&original_message, &public_key);
    let message = RSA::decrypt(&cipher_text, &private_key);

    assert_eq!(cipher_text, BigInt::from(2790));
    assert_eq!(message, BigInt::from(65));

    let cipher_text = RSA::encrypt_vec(&original_message.to_bytes_be().1, &public_key);
    assert_eq!(cipher_text, BigInt::from(2790));

    println!("Finished!")
}

//! Took from here how to work with no_std and std
//! https://github.com/KodrAus/rust-no-std

#![no_std]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;
#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[allow(clippy::many_single_char_names)]
pub mod blind;
#[allow(clippy::many_single_char_names)]
pub mod elgamal;
#[allow(clippy::many_single_char_names)]
mod math;
#[allow(clippy::many_single_char_names)]
pub mod proof;
#[allow(clippy::many_single_char_names)]
pub mod rsa;

pub mod hash;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

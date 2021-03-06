//! Implementations of JWT signing / verification algorithms.

#[cfg(feature = "secp256k1")]
mod es256k;
mod hmacs;
#[cfg(feature = "k256")]
mod k256;
#[cfg(feature = "p256")]
mod p256;
// Alternative EdDSA implementations.
#[cfg(feature = "ed25519-compact")]
mod eddsa_compact;
#[cfg(feature = "ed25519-dalek")]
mod eddsa_dalek;
#[cfg(feature = "exonum-crypto")]
mod eddsa_sodium;
#[cfg(feature = "rsa")]
mod rsa;

#[cfg(feature = "ed25519-compact")]
pub use self::eddsa_compact::*;
#[cfg(feature = "ed25519-dalek")]
pub use self::eddsa_dalek::Ed25519;
#[cfg(feature = "exonum-crypto")]
pub use self::eddsa_sodium::Ed25519;
#[cfg(feature = "secp256k1")]
pub use self::es256k::*;
pub use self::hmacs::*;
#[cfg(feature = "k256")]
pub use self::k256::*;
#[cfg(feature = "p256")]
pub use self::p256::*;
#[cfg(feature = "rsa")]
pub use self::rsa::{
    Padding, Ps256, Ps384, Ps512, Rs256, Rs384, Rs512, Rsa, RsaSigningKey, RsaVerifyingKey,
};

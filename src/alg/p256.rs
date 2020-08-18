use p256::{
    ecdsa::{signature::RandomizedSigner, signature::Verifier as _, Signature, Signer, Verifier},
    elliptic_curve::Generate,
    PublicKey, SecretKey,
};
use rand_core::{CryptoRng, RngCore};

use std::borrow::Cow;
use std::convert::TryFrom;

use crate::error::ValidationError;
use crate::{Algorithm, AlgorithmSignature};

impl AlgorithmSignature for Signature {
    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        Signature::try_from(slice).map_err(|e| anyhow::anyhow!(e))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.as_ref().to_vec())
    }
}

/// A verification key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Es256kVerifyingKey(PublicKey);

impl AsRef<PublicKey> for Es256kVerifyingKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

impl Es256kVerifyingKey {
    /// Create a verification key from a slice.
    pub fn from_slice(raw: &[u8]) -> anyhow::Result<Es256kVerifyingKey> {
        Ok(Es256kVerifyingKey(
            PublicKey::from_bytes(raw).ok_or(ValidationError::InvalidPublicKey)?,
        ))
    }

    /// Return the key as raw bytes.
    pub fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.as_ref().as_bytes().to_vec())
    }
}

/// A signing key.
#[derive(Debug)]
pub struct Es256kSigningKey(SecretKey);

impl AsRef<SecretKey> for Es256kSigningKey {
    fn as_ref(&self) -> &SecretKey {
        &self.0
    }
}

impl Es256kSigningKey {
    /// Create a signing key from a slice.
    pub fn from_slice(raw: &[u8]) -> anyhow::Result<Es256kSigningKey> {
        Ok(Es256kSigningKey(SecretKey::from_bytes(raw)?))
    }

    /// Convert a signing key to a verification key.
    pub fn to_verifying_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.0, true).unwrap()
    }
}

/// Algorithm implementing elliptic curve digital signatures (ECDSA) on the p256 curve.
///
/// The algorithm does not fix the choice of the message digest algorithm; instead,
/// it is provided as a type parameter. SHA-256 is the default parameter value,
/// but it can be set to any cryptographically secure hash function with 32-byte output
/// (e.g., SHA3-256).
///
/// *This type is available if the crate is built with the `p256` feature.*
#[derive(Debug)]
pub struct Es256k<R: CryptoRng + RngCore> {
    rng: R,
}

impl<R: CryptoRng + RngCore> Es256k<R> {
    /// Create an Es256k structure that uses the provided RNG
    pub fn new(rng: R) -> Self {
        Es256k { rng }
    }
}

impl<R: CryptoRng + RngCore> Algorithm for Es256k<R> {
    type SigningKey = Es256kSigningKey;
    type VerifyingKey = Es256kVerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ES256")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let signer = Signer::new(signing_key.as_ref()).unwrap();
        signer.sign_with_rng(&mut rand_core::OsRng, message)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let verifier = match Verifier::new(verifying_key.as_ref()) {
            Err(_) => return false,
            Ok(verifier) => verifier,
        };
        verifier.verify(&message, signature).is_ok()
    }
}

impl<R: CryptoRng + RngCore> Es256k<R> {
    /// Generate a new key pair.
    pub fn generate(&mut self) -> (Es256kSigningKey, Es256kVerifyingKey) {
        let signing_key = Es256kSigningKey(SecretKey::generate(&mut self.rng));
        let verifying_key =
            Es256kVerifyingKey(PublicKey::from_secret_key(signing_key.as_ref(), true).unwrap());
        (signing_key, verifying_key)
    }
}

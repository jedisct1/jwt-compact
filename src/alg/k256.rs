use k256::{
    ecdsa::{signature::RandomizedSigner, signature::Verifier as _, Signature, Signer, Verifier},
    elliptic_curve::Generate,
    PublicKey, SecretKey,
};
use rand_core::{CryptoRng, RngCore};

use std::borrow::Cow;

use crate::error::ValidationError;
use crate::{Algorithm, AlgorithmSignature};

impl AlgorithmSignature for Signature {
    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        if slice.len() != 64 {
            return Err(anyhow::anyhow!("Invalid signature encoding"));
        }
        let r = &slice[..32];
        let s = &slice[32..];
        Ok(Signature::from_scalars(r.into(), s.into()))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        let r = self.r().as_slice();
        let s = self.s().as_slice();
        let mut v: Vec<u8> = Vec::with_capacity(r.len() + s.len());
        v.extend_from_slice(r);
        v.extend_from_slice(s);
        Cow::Owned(v)
    }
}

/// A verification key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Es256VerifyingKey(PublicKey);

impl AsRef<PublicKey> for Es256VerifyingKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

impl Es256VerifyingKey {
    /// Create a verification key from a slice.
    pub fn from_slice(raw: &[u8]) -> anyhow::Result<Es256VerifyingKey> {
        Ok(Es256VerifyingKey(
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
pub struct Es256SigningKey(SecretKey);

impl AsRef<SecretKey> for Es256SigningKey {
    fn as_ref(&self) -> &SecretKey {
        &self.0
    }
}

impl Es256SigningKey {
    /// Create a signing key from a slice.
    pub fn from_slice(raw: &[u8]) -> anyhow::Result<Es256SigningKey> {
        Ok(Es256SigningKey(SecretKey::from_bytes(raw)?))
    }

    /// Convert a signing key to a verification key.
    pub fn to_verifying_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.0, true).unwrap()
    }
}

/// Algorithm implementing elliptic curve digital signatures (ECDSA) on the secp256k1 curve.
///
/// The algorithm does not fix the choice of the message digest algorithm; instead,
/// it is provided as a type parameter. SHA-256 is the default parameter value,
/// but it can be set to any cryptographically secure hash function with 32-byte output
/// (e.g., SHA3-256).
///
/// *This type is available if the crate is built with the `k256` feature.*
#[derive(Debug)]
pub struct Es256<R: CryptoRng + RngCore> {
    rng: R,
}

impl<R: CryptoRng + RngCore> Es256<R> {
    /// Create an Es256 structure that uses the provided RNG
    pub fn new(rng: R) -> Self {
        Es256 { rng }
    }
}

impl<R: CryptoRng + RngCore> Algorithm for Es256<R> {
    type SigningKey = Es256SigningKey;
    type VerifyingKey = Es256VerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ES256K")
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

impl<R: CryptoRng + RngCore> Es256<R> {
    /// Generate a new key pair.
    pub fn generate(&mut self) -> (Es256SigningKey, Es256VerifyingKey) {
        let signing_key = Es256SigningKey(SecretKey::generate(&mut self.rng));
        let verifying_key =
            Es256VerifyingKey(PublicKey::from_secret_key(signing_key.as_ref(), true).unwrap());
        (signing_key, verifying_key)
    }
}

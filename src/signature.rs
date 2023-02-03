//! Trait types for signature methods

#[cfg(feature = "rust_crypto")]
use k256::{
    schnorr::{CryptoRngCore, Signature, SigningKey},
    NonZeroScalar, PublicKey,
};

/// Adaptor signatures prover must implement this trait
///
/// Visit [`scriptless-scripts`](https://suredbits.com/schnorr-applications-scriptless-scripts/) for details
pub trait AdaptorSigner {
    fn adaptor_sign_with_rng<RNG>(
        &self,
        rng: &mut RNG,
        t: &PublicKey,
        msg_digest: &[u8; 32],
    ) -> anyhow::Result<Signature>
    where
        RNG: CryptoRngCore;
}

pub trait RepairAdaptorSignature {
    /// Try assmble taproot Schnorr signature,
    /// Return []
    fn repair_adaptor_signature(
        &self,
        msg_digest: &[u8; 32],
        adaptor_sig: &Signature,
        secret_key: &SigningKey,
    ) -> anyhow::Result<Signature>;
}

pub trait SecretExtractor {
    fn extract_secret(&self, tweaked_signature: Signature) -> anyhow::Result<NonZeroScalar>;
}

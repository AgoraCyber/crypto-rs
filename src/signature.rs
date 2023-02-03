//! Trait types for signature methods

#[cfg(feature = "rust_crypto")]
use k256::{
    schnorr::{CryptoRngCore, Signature, SigningKey, VerifyingKey},
    NonZeroScalar,
};

/// Adaptor signatures prover must implement this trait
///
/// Visit [`scriptless-scripts`](https://suredbits.com/schnorr-applications-scriptless-scripts/) for details
pub trait AdaptorSigner {
    /// Create new tweaked signature [`(R',s')`] for harded `msg_digest`.
    ///
    /// The caller must provider a [`Crypto randomness generator`](CryptoRngCore) to invoke this function
    ///
    /// The parameter `t` is the public key of verifier's payment secret.
    ///
    /// For compatibility with [`BIP340`](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki),
    /// only those public key whose [`point`](k256::AffinePoint) is an even point are acceptable,
    /// on the other hand [`VerifyingKey`] offers this type of guarantee.
    fn sign_with_rng<RNG>(
        &self,
        rng: &mut RNG,
        t: &VerifyingKey,
        msg_digest: &[u8; 32],
    ) -> anyhow::Result<Signature>
    where
        RNG: CryptoRngCore;
}

pub trait RepairAdaptorSignature {
    /// Try assmble taproot Schnorr signature `(R,s)` with payment secret from tweaked signature `(R',s')`,
    fn repair_signature(
        &self,
        msg_digest: &[u8; 32],
        adaptor_sig: &Signature,
        secret_key: &SigningKey,
    ) -> anyhow::Result<Signature>;
}

pub trait SecretExtractor {
    fn extract_secret(&self, tweaked_signature: Signature) -> anyhow::Result<NonZeroScalar>;
}

//! Taproot Schnorr random genreator
//!
//! Visit [`here`](https://merlin.cool/transcript/rng.html#deterministic-and-synthetic-nonce-generation)
//! to find out additional information about `Deterministic and synthetic nonce generation`
//!
//! The codes in this mod is ported from [`sign_prehash_with_aux_rand`](k256::schnorr::SigningKey::sign_prehash_with_aux_rand) method

use k256::{
    elliptic_curve::AffineXCoordinate,
    schnorr::SigningKey,
    sha2::{Digest, Sha256},
    NonZeroScalar,
};

pub const AUX_TAG: &[u8] = b"BIP0340/aux";
pub const NONCE_TAG: &[u8] = b"BIP0340/nonce";
pub const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

pub fn tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

pub fn synthetic_random(
    secret_key: &SigningKey,
    msg_digest: &[u8; 32],
    aux_rand: &[u8; 32],
) -> anyhow::Result<SigningKey> {
    let mut t = tagged_hash(AUX_TAG).chain_update(aux_rand).finalize();

    for (a, b) in t.iter_mut().zip(secret_key.to_bytes().iter()) {
        *a ^= b
    }

    let rand = tagged_hash(NONCE_TAG)
        .chain_update(t)
        .chain_update(secret_key.as_ref().as_affine().x())
        .chain_update(msg_digest)
        .finalize();

    Ok(NonZeroScalar::try_from(&*rand).map(SigningKey::from)?)
}

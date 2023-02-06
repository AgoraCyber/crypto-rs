//! An implementation of [`Adaptor signatures`](https://suredbits.com/schnorr-applications-scriptless-scripts/) using rust_crypto as a backend

use k256::{
    elliptic_curve::{
        ops::{LinearCombination, Reduce},
        AffineXCoordinate,
    },
    schnorr::{CryptoRngCore, Signature, SigningKey, VerifyingKey},
    sha2::Digest,
    AffinePoint, FieldElement, NonZeroScalar, ProjectivePoint, Scalar, U256,
};

use crate::{
    error::SchnorrError,
    random::{synthetic_random, tagged_hash, CHALLENGE_TAG},
    signature::{AdaptorSigner, RepairAdaptorSignature, SecretExtractor},
};

impl AdaptorSigner for SigningKey {
    fn adaptor_sign_with_rng<RNG>(
        &self,
        rng: &mut RNG,
        t: &VerifyingKey,
        msg_digest: &[u8; 32],
    ) -> anyhow::Result<k256::schnorr::Signature>
    where
        RNG: CryptoRngCore,
    {
        // Synthetic random generate
        let mut aux_rand = [0u8; 32];

        rng.fill_bytes(&mut aux_rand);

        let k_star = synthetic_random(self, msg_digest, &aux_rand)?;

        // R' point
        let r_star: ProjectivePoint = AffinePoint::from(k_star.as_ref()).into();

        let t = AffinePoint::from(t);

        // Generate R = 𝑅′+𝑇
        let r = FieldElement::from_bytes(&(r_star + t).to_affine().x())
            .unwrap()
            .normalize();

        let e = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain_update(r.to_bytes())
                .chain_update(self.as_ref().to_bytes())
                .chain_update(msg_digest)
                .finalize(),
        );

        let r_star = FieldElement::from_bytes(&r_star.to_affine().x())
            .unwrap()
            .normalize();

        // Calculate 𝑠′=𝑘′+𝐻(𝑋,𝑅′+𝑇,𝑚)∗𝑥
        let s_star = **k_star.as_nonzero_scalar() + e * **self.as_nonzero_scalar();

        // Workaround to create Signature structure instance outside of `k256` crate

        let mut sig_bytes = [0; Signature::BYTE_SIZE];
        let (r_bytes, s_bytes) = sig_bytes.split_at_mut(Signature::BYTE_SIZE / 2);

        r_bytes.copy_from_slice(&r_star.to_bytes());
        s_bytes.copy_from_slice(&s_star.to_bytes());

        Ok(sig_bytes.as_slice().try_into()?)
    }
}

impl RepairAdaptorSignature for VerifyingKey {
    fn repair_tweaked_signature(
        &self,
        msg_digest: &[u8; 32],
        adaptor_sig: &Signature,
        secret_key: &SigningKey,
    ) -> anyhow::Result<Signature> {
        let sig_bytes = adaptor_sig.to_bytes();

        let (r_bytes, s_bytes) = sig_bytes.split_at(Signature::BYTE_SIZE / 2);

        let r_star: ProjectivePoint = VerifyingKey::from_bytes(&r_bytes)?.as_affine().into();

        let s_star = NonZeroScalar::try_from(s_bytes)?;

        // Generate R = 𝑅′+𝑇
        let r = FieldElement::from_bytes(
            &(r_star + secret_key.verifying_key().as_affine())
                .to_affine()
                .x(),
        )
        .unwrap()
        .normalize();

        let e = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain_update(r.to_bytes())
                .chain_update(self.to_bytes())
                .chain_update(msg_digest)
                .finalize(),
        );

        let y: ProjectivePoint = self.as_affine().into();

        #[allow(non_snake_case)]
        let r_expect =
            ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &s_star, &y, &-e).to_affine();

        // check if generated R' Y Coordinate is not odd
        if r_expect == r_star.to_affine() {
            let s = *s_star + **secret_key.as_nonzero_scalar();

            // Workaround to create Signature structure instance outside of `k256` crate

            let mut sig_bytes = [0; Signature::BYTE_SIZE];
            let (r_bytes, s_bytes) = sig_bytes.split_at_mut(Signature::BYTE_SIZE / 2);

            r_bytes.copy_from_slice(&r.to_bytes());
            s_bytes.copy_from_slice(&s.to_bytes());

            Ok(sig_bytes.as_slice().try_into()?)
        } else {
            Err(SchnorrError::IncorrectAdaptorSig.into())
        }
    }
}

impl SecretExtractor for Signature {
    fn extract_secret(&self, tweaked_signature: Signature) -> anyhow::Result<NonZeroScalar> {
        let sig_bytes = tweaked_signature.to_bytes();

        let (_, s_bytes) = sig_bytes.split_at(Signature::BYTE_SIZE / 2);

        let s_star = NonZeroScalar::try_from(s_bytes)?;

        let sig_bytes = self.to_bytes();

        let (_, s_bytes) = sig_bytes.split_at(Signature::BYTE_SIZE / 2);

        let s = NonZeroScalar::try_from(s_bytes)?;

        Option::from(NonZeroScalar::new(*s - *s_star)).ok_or(SchnorrError::NonZeroScalar.into())
    }
}

#[cfg(test)]
mod tests {
    use k256::{
        elliptic_curve::{
            sec1::{FromEncodedPoint, ToEncodedPoint},
            subtle::Choice,
        },
        schnorr::{SigningKey, VerifyingKey},
        EncodedPoint, FieldElement, PublicKey,
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_odd() {
        _ = pretty_env_logger::try_init();

        let key = SigningKey::random(&mut OsRng);

        let point = key.verifying_key().as_affine().to_encoded_point(false);

        let pub_key = PublicKey::from_encoded_point(&point).unwrap();

        let y = FieldElement::from_bytes(point.y().unwrap()).unwrap();

        assert_eq!(
            bool::from(y.normalize().is_odd()),
            bool::from(Choice::from(0))
        );

        VerifyingKey::try_from(pub_key).expect("Convert even point to verify key");

        let y = -y;

        assert_eq!(
            bool::from(y.normalize().is_odd()),
            bool::from(Choice::from(1))
        );

        let point = EncodedPoint::from_affine_coordinates(point.x().unwrap(), &y.to_bytes(), false);

        let pub_key = PublicKey::from_encoded_point(&point).unwrap();

        VerifyingKey::try_from(pub_key).expect_err("From odd point is not allowed");
    }
}

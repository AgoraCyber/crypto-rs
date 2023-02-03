use k256::{
    schnorr::{signature::hazmat::PrehashVerifier, SigningKey},
    sha2::{Digest, Sha256},
};
use rand::rngs::OsRng;
use schnorr_rs::signature::{AdaptorSigner, RepairAdaptorSignature, SecretExtractor};

#[test]
fn test_adaptor_repair() {
    let alice_signin_key = SigningKey::random(&mut OsRng);

    let bob_secret_key = SigningKey::random(&mut OsRng);

    let bob_secret_pubkey = bob_secret_key.verifying_key();

    let harshed = Sha256::new().chain_update(b"hello").finalize().into();

    let tweaked_signature = alice_signin_key
        .sign_with_rng(&mut OsRng, &bob_secret_pubkey, &harshed)
        .expect("Sign");

    let verify_key = alice_signin_key.verifying_key();

    verify_key
        .verify_prehash(&harshed, &tweaked_signature)
        .expect_err("Tweaked signature must not passed");

    let signature = verify_key
        .repair_signature(&harshed, &tweaked_signature, &bob_secret_key)
        .expect("Repair");

    verify_key
        .verify_prehash(&harshed, &signature)
        .expect("Success");

    // get bob secret key

    let secret = signature
        .extract_secret(tweaked_signature)
        .expect("extract secret");

    assert_eq!(
        secret.to_bytes(),
        bob_secret_key.as_nonzero_scalar().to_bytes(),
        "Shared secret"
    );
}

// TODO: test if check odd R

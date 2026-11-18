// SPDX-License-Identifier: MIT

use std::sync::OnceLock;

use k256::ecdsa::Signature;
use libp2p_identity::{KeyType, PublicKey};
use secp256k1::{Message, Secp256k1, VerifyOnly};
use sha2::{Digest, Sha256};

pub(crate) fn verify(
    key: PublicKey,
    message: &[u8],
    signature: &[u8],
    #[cfg(feature = "verification-sample")] source: &libp2p_identity::PeerId,
) -> bool {
    if key.key_type() != KeyType::Secp256k1 {
        return key.verify(message, signature);
    }
    let Ok(key) = key.try_into_secp256k1() else {
        return false;
    };

    let digest = Sha256::digest(message).into();
    let valid = verify_hash(&key, digest, signature);
    #[cfg(feature = "verification-sample")]
    if valid {
        crate::verification_sample::observe(source, &digest, signature);
    }
    valid
}

fn verify_hash(key: &libp2p_identity::secp256k1::PublicKey, digest: [u8; 32], der: &[u8]) -> bool {
    static CONTEXT: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();

    // Keep libp2p-identity's strict DER parser and its acceptance of high-S signatures.
    let Ok(strict) = Signature::from_der(der) else {
        return false;
    };
    let Ok(mut signature) = secp256k1::ecdsa::Signature::from_compact(&strict.to_bytes()) else {
        return false;
    };
    signature.normalize_s();

    let Ok(key) = secp256k1::PublicKey::from_slice(&key.to_bytes_uncompressed()) else {
        return false;
    };
    CONTEXT
        .get_or_init(Secp256k1::verification_only)
        .verify_ecdsa(&Message::from_digest(digest), &signature, &key)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use libp2p_identity::secp256k1::{Keypair, SecretKey};

    use super::*;

    #[test]
    fn agrees_with_identity_verifier_on_both_s_values_and_invalid_inputs() {
        for seed in 1..=32u8 {
            let keypair = Keypair::from(SecretKey::try_from_bytes([seed; 32]).unwrap());
            let key = keypair.public();
            let other = Keypair::from(SecretKey::try_from_bytes([seed + 32; 32]).unwrap());
            let message = [seed; 256];
            let digest: [u8; 32] = Sha256::digest(message).into();
            let der = keypair.secret().sign(&message);
            let (r, s) = Signature::from_der(&der).unwrap().split_scalars();
            let opposite_s = Signature::from_scalars(r.to_bytes(), (-*s.as_ref()).to_bytes())
                .unwrap()
                .to_der();

            for signature in [der.as_slice(), opposite_s.as_bytes()] {
                assert!(key.verify_hash(&digest, signature));
                assert!(verify_hash(key, digest, signature));
            }

            let mut wrong_digest = digest;
            wrong_digest[0] ^= 1;
            assert!(!key.verify_hash(&wrong_digest, &der));
            assert!(!verify_hash(key, wrong_digest, &der));
            assert!(!other.public().verify_hash(&digest, &der));
            assert!(!verify_hash(other.public(), digest, &der));

            let mut trailing_data = der.clone();
            trailing_data.push(0);
            let zero_scalar = [0x30, 6, 2, 1, 0, 2, 1, 1];
            for invalid in [
                trailing_data.as_slice(),
                &der[..der.len() - 1],
                &zero_scalar,
            ] {
                assert!(!key.verify_hash(&digest, invalid));
                assert!(!verify_hash(key, digest, invalid));
            }
        }
    }
}

// SPDX-License-Identifier: MIT

use std::sync::{LazyLock, Mutex, PoisonError};

use libp2p_identity::PeerId;
use sha2::{Digest, Sha256};
use web_time::Instant;

const SHARDS: usize = 16;
const SLOTS_PER_SHARD: usize = 512;
const WINDOW: std::time::Duration = std::time::Duration::from_secs(5);

static SAMPLES: LazyLock<Samples> = LazyLock::new(Samples::new);

/// Observe a successful secp256k1 verification after binding the key to the source.
pub(crate) fn observe(source: &PeerId, prehash: &[u8; 32], signature: &[u8]) {
    // Select 1/64 of signed preimages so every copy of a sampled message is observed.
    if prehash[0] >= 4 {
        return;
    }

    let key = fingerprint(source, prehash, signature);
    let result = SAMPLES.record(key).label();
    metrics::counter!("gossipsub_verification_sample_total", "result" => result).increment(1);
}

fn fingerprint(source: &PeerId, prehash: &[u8; 32], signature: &[u8]) -> [u8; 32] {
    // The bound secp256k1 PeerId contains the canonical public key.
    let source = source.as_ref();
    let mut hash = Sha256::new();
    hash.update(source.code().to_be_bytes());
    hash.update([source.size()]);
    hash.update(source.digest());
    hash.update(prehash);
    hash.update(signature);
    hash.finalize().into()
}

struct Samples {
    shards: [Mutex<Vec<Option<Observation>>>; SHARDS],
}

struct Observation {
    key: [u8; 32],
    seen_at: Instant,
}

#[derive(Debug, Eq, PartialEq)]
enum ResultKind {
    New,
    Repeat,
    Collision,
}

impl ResultKind {
    fn label(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Repeat => "repeat",
            Self::Collision => "collision",
        }
    }
}

impl Samples {
    fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| {
                Mutex::new(
                    std::iter::repeat_with(|| None)
                        .take(SLOTS_PER_SHARD)
                        .collect(),
                )
            }),
        }
    }

    fn record(&self, key: [u8; 32]) -> ResultKind {
        let index = usize::from(u16::from_be_bytes([key[0], key[1]]));
        let mut shard = self.shards[index % SHARDS]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let slot = &mut shard[index / SHARDS % SLOTS_PER_SHARD];
        record_at(slot, key, Instant::now())
    }
}

fn record_at(slot: &mut Option<Observation>, key: [u8; 32], now: Instant) -> ResultKind {
    let result = match slot {
        Some(previous) if now.duration_since(previous.seen_at) < WINDOW => {
            if previous.key == key {
                ResultKind::Repeat
            } else {
                ResultKind::Collision
            }
        }
        _ => ResultKind::New,
    };
    *slot = Some(Observation { key, seen_at: now });
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_repeats_and_live_replacements_with_a_sliding_window() {
        let mut slot = None;
        let started = Instant::now();
        let first = [0; 32];
        let second = [1; 32];
        let within_window = WINDOW - std::time::Duration::from_millis(1);

        assert_eq!(record_at(&mut slot, first, started), ResultKind::New);
        assert_eq!(
            record_at(&mut slot, first, started + within_window),
            ResultKind::Repeat,
        );
        assert_eq!(
            record_at(&mut slot, second, started + within_window * 2),
            ResultKind::Collision,
        );
        assert_eq!(
            record_at(&mut slot, second, started + within_window * 2 + WINDOW),
            ResultKind::New,
        );
    }

    #[test]
    fn fingerprints_bind_source_prehash_and_der() {
        let source = PeerId::from_bytes(&[0, 1, 0]).unwrap();
        let other_source = PeerId::from_bytes(&[0, 1, 1]).unwrap();
        let sample = fingerprint(&source, &[0; 32], &[1, 2, 3]);
        assert_ne!(sample, fingerprint(&other_source, &[0; 32], &[1, 2, 3]));
        assert_ne!(sample, fingerprint(&source, &[1; 32], &[1, 2, 3]));
        assert_ne!(sample, fingerprint(&source, &[0; 32], &[1, 2, 4]));
    }
}

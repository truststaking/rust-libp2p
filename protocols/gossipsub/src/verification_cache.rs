// SPDX-License-Identifier: MIT

use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Duration;

use sha2::{Digest, Sha256};
use web_time::Instant;

use crate::rpc_proto::proto;

const SHARDS: usize = 64;
const SLOTS_PER_SHARD: usize = 512;
const TTL: Duration = Duration::from_secs(5);

type Fingerprint = [u8; 32];
type Shard = Mutex<Box<[Option<Entry>]>>;

static CACHE: LazyLock<[Shard; SHARDS]> = LazyLock::new(|| {
    std::array::from_fn(|_| Mutex::new(vec![None; SLOTS_PER_SHARD].into_boxed_slice()))
});

#[derive(Clone, Copy)]
struct Entry {
    fingerprint: Fingerprint,
    verified_at: Instant,
}

impl Entry {
    fn matches(&self, fingerprint: &Fingerprint, now: Instant) -> bool {
        &self.fingerprint == fingerprint && now.duration_since(self.verified_at) < TTL
    }
}

pub(crate) fn fingerprint(message: &proto::Message) -> Fingerprint {
    let proto::Message {
        from,
        data,
        seqno,
        topic,
        signature,
        key,
    } = message;
    let mut hash = Sha256::new();
    // Fixed field order and length prefixes bind all fields, including optional presence.
    for field in [
        from.as_deref(),
        data.as_deref(),
        seqno.as_deref(),
        Some(topic.as_bytes()),
        signature.as_deref(),
        key.as_deref(),
    ] {
        match field {
            Some(bytes) => {
                hash.update((bytes.len() as u64).to_be_bytes());
                hash.update(bytes);
            }
            None => hash.update(u64::MAX.to_be_bytes()),
        }
    }
    hash.finalize().into()
}

fn slot(fingerprint: &Fingerprint) -> (&'static Shard, usize) {
    let index = usize::from(u16::from_be_bytes([fingerprint[0], fingerprint[1]]));
    (&CACHE[index % SHARDS], index / SHARDS % SLOTS_PER_SHARD)
}

pub(crate) fn contains(fingerprint: &Fingerprint) -> bool {
    let (shard, index) = slot(fingerprint);
    let hit = {
        let entries = shard.lock().unwrap_or_else(PoisonError::into_inner);
        entries[index].is_some_and(|entry| entry.matches(fingerprint, Instant::now()))
    };
    if fingerprint[2] < 4 {
        let result = if hit { "hit" } else { "miss" };
        metrics::counter!("gossipsub_verification_cache_sample_total", "result" => result)
            .increment(1);
    }
    hit
}

/// Store only after strict signature verification and source/key binding succeed.
pub(crate) fn insert(fingerprint: Fingerprint) {
    let (shard, index) = slot(&fingerprint);
    let mut entries = shard.lock().unwrap_or_else(PoisonError::into_inner);
    entries[index] = Some(Entry {
        fingerprint,
        verified_at: Instant::now(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_collision_and_expiration_never_match() {
        let fingerprint = [0; 32];
        let mut other = fingerprint;
        other[31] = 1;
        assert!(std::ptr::eq(slot(&fingerprint).0, slot(&other).0));
        assert_eq!(slot(&fingerprint).1, slot(&other).1);

        let verified_at = Instant::now();
        let entry = Entry {
            fingerprint,
            verified_at,
        };
        assert!(entry.matches(&fingerprint, verified_at));
        assert!(!entry.matches(&other, verified_at));
        assert!(!entry.matches(&fingerprint, verified_at + TTL));
    }

    #[test]
    fn field_boundaries_and_presence_are_part_of_fingerprint() {
        let mut message = proto::Message {
            from: Some(vec![1]),
            data: Some(vec![2]),
            ..Default::default()
        };
        let original = fingerprint(&message);
        message.from = Some(vec![1, 2]);
        message.data = Some(vec![]);
        assert_ne!(original, fingerprint(&message));
        let empty = fingerprint(&message);
        message.data = None;
        assert_ne!(empty, fingerprint(&message));
    }
}

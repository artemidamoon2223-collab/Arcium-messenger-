use super::*;

fn wait(k: u8, first: u64, last: u64) -> FarWait {
    FarWait {
        chain: [k; 32],
        first,
        last,
        stored_last: Some(last),
    }
}

/// What the caller does once `waits` is stored.
fn stored(waits: &mut FarWaits) {
    for w in waits.iter_mut() {
        w.stored_last = Some(w.last);
    }
}

#[test]
fn a_far_wait_record_reads_back_what_was_written() {
    for n in 0..=FAR_CHAINS_PER_SESSION {
        let waits: FarWaits = (0..n)
            .map(|i| {
                let i = u8::try_from(i).unwrap();
                wait(i + 1, 1_000 * u64::from(i), u64::MAX - u64::from(i))
            })
            .collect();
        let bytes = pack_far_waits(&waits);
        assert_eq!(bytes.len(), 2 + FAR_WAIT_ENTRY_LEN * n);
        assert_eq!(&bytes[..2], &[1, u8::try_from(n).unwrap()]);
        assert_eq!(unpack_far_waits(&bytes), Some(waits), "{n} chains");
    }
    // Big-endian, chain first.
    let bytes = pack_far_waits(&[wait(7, 0x0102, 0x0304)]);
    assert_eq!(&bytes[2..34], &[7; 32]);
    assert_eq!(&bytes[34..42], &0x0102u64.to_be_bytes());
    assert_eq!(&bytes[42..50], &0x0304u64.to_be_bytes());
}

#[test]
fn a_damaged_far_wait_record_is_refused_by_the_parser() {
    let good = pack_far_waits(&[wait(1, 5, 6), wait(2, 7, 8)]);
    assert!(unpack_far_waits(&good).is_some());
    let mut other_version = good.clone();
    other_version[0] = 2;
    let mut more_than_held = pack_far_waits(&vec![wait(1, 1, 1); FAR_CHAINS_PER_SESSION + 1]);
    // Distinct chains, so only the count is wrong.
    for (i, e) in more_than_held[2..]
        .as_chunks_mut::<FAR_WAIT_ENTRY_LEN>()
        .0
        .iter_mut()
        .enumerate()
    {
        e[0] = u8::try_from(i).unwrap();
    }
    let mut count_too_high = good.clone();
    count_too_high[1] = 3;
    let repeated = pack_far_waits(&[wait(1, 5, 6), wait(1, 7, 8)]);
    for bad in [
        Vec::new(),
        vec![1],
        other_version,
        more_than_held,
        count_too_high,
        good[..good.len() - 1].to_vec(),
        [&good[..], &[0]].concat(),
        repeated,
    ] {
        assert_eq!(unpack_far_waits(&bad), None, "{bad:?}");
    }
}

#[test]
fn a_new_chain_starts_waiting_and_asks_to_be_stored() {
    let mut waits = FarWaits::new();
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000), (1_000, true));
    assert_eq!(waits.len(), 1);
    assert_eq!((waits[0].chain, waits[0].first, waits[0].last), ([1; 32], 1_000, 1_000));
}

/// A write that failed is asked for again at the chain's next sighting,
/// not a minute later.
#[test]
fn a_chain_whose_write_failed_asks_again() {
    let mut waits = FarWaits::new();
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000), (1_000, true));
    // Not stored.
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_500), (1_000, true));
    stored(&mut waits);
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 2_000), (1_000, false));
    // A clock set back starts the wait again, and asks again until stored.
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 500), (500, true));
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 600), (500, true));
}

#[test]
fn a_chain_seen_again_keeps_its_first_sighting_and_stores_its_last_once_a_minute() {
    let mut waits = vec![wait(1, 1_000, 1_000)];
    let step = FAR_WAIT_LAST_STEP_MS;
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000 + step - 1), (1_000, false));
    assert_eq!(waits[0].last, 1_000 + step - 1, "exact in memory");
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000 + step), (1_000, true));
    stored(&mut waits);
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000 + 2 * step - 1), (1_000, false));
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000 + 2 * step), (1_000, true));
    // An earlier reading after the first sighting moves nothing back.
    stored(&mut waits);
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 2_000), (1_000, false));
    assert_eq!(waits, vec![wait(1, 1_000, 1_000 + 2 * step)]);
}

#[test]
fn a_clock_set_back_before_the_first_sighting_starts_the_wait_again() {
    let mut waits = vec![wait(1, 50_000, 90_000), wait(2, 10_000, 20_000)];
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 40_000), (40_000, true));
    assert_eq!((waits[0].first, waits[0].last), (40_000, 40_000));
    assert_eq!(waits[1], wait(2, 10_000, 20_000), "other chains untouched");
}

#[test]
fn a_new_chain_drops_the_one_seen_least_recently() {
    let mut waits: FarWaits = (1..=4u8).map(|k| wait(k, 0, 100 * u64::from(k))).collect();
    waits[0].last = 900; // chain 1 seen most recently, chain 2 least
    assert_eq!(note_far_sighting(&mut waits, [9; 32], 1_000), (1_000, true));
    let chains: Vec<u8> = waits.iter().map(|w| w.chain[0]).collect();
    assert_eq!(chains, vec![1, 3, 4, 9]);
}

/// The order of dropping follows the exact last sighting, not the one
/// stored a minute ago.
#[test]
fn dropping_follows_the_last_sighting_in_memory() {
    let mut waits: FarWaits = (1..=4u8).map(|k| wait(k, 0, 10 + u64::from(k))).collect();
    // Chain 1 is seen again within the minute: not stored, but later
    // than the others.
    assert_eq!(note_far_sighting(&mut waits, [1; 32], 100), (0, false));
    note_far_sighting(&mut waits, [9; 32], 200);
    let chains: Vec<u8> = waits.iter().map(|w| w.chain[0]).collect();
    assert_eq!(chains, vec![1, 3, 4, 9]);
}

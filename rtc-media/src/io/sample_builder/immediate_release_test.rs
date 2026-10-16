use super::*;
use rtp::codec::{h264::H264Packet, h265::H265Packet};

fn packet(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Packet {
    Packet {
        header: rtp::Header {
            sequence_number: sequence,
            timestamp,
            marker,
            ..Default::default()
        },
        payload: Bytes::copy_from_slice(payload),
        ..Default::default()
    }
}

#[test]
fn default_video_still_waits_for_duration_lookahead() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000);
    builder.push(packet(10, 2400, true, &[0x26, 0x01, 0xab]));
    assert!(builder.pop().is_none());
    builder.push(packet(11, 3200, true, &[0x26, 0x01, 0xcd]));
    let sample = builder.pop().unwrap();
    assert_eq!(sample.packet_timestamp, 2400);
    assert_eq!(sample.duration, Duration::from_secs_f64(800.0 / 24_000.0));
}

#[test]
fn h265_releases_marked_picture_without_next_packet_and_only_once() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    builder.push(packet(10, 2400, true, &[0x26, 0x01, 0xab]));
    let sample = builder.pop().expect("Complete video must not wait for a future packet");
    assert_eq!(sample.data.as_ref(), &[0, 0, 0, 1, 0x26, 0x01, 0xab]);
    assert_eq!(sample.packet_timestamp, 2400);
    assert_eq!(sample.duration, Duration::ZERO);
    assert_eq!(sample.prev_dropped_packets, 0);
    assert!(builder.pop().is_none());
    assert_eq!(builder.flush(), (None, false));
    builder.push(packet(11, 3200, true, &[0x26, 0x01, 0xcd]));
    assert_eq!(builder.pop().unwrap().packet_timestamp, 3200);
}

#[test]
fn h264_reassembles_fragments_before_immediate_release() {
    let mut builder = SampleBuilder::new(200, H264Packet::default(), 24_000)
        .with_immediate_partition_release();
    builder.push(packet(10, 2400, false, &[0x7c, 0x85, 0xaa]));
    assert!(builder.pop().is_none());
    builder.push(packet(11, 2400, true, &[0x7c, 0x45, 0xbb]));
    let sample = builder.pop().unwrap();
    assert_eq!(sample.data.as_ref(), &[0, 0, 0, 1, 0x65, 0xaa, 0xbb]);
    assert_eq!(sample.prev_dropped_packets, 0);
}

#[test]
fn h265_waits_for_gap_repair_even_when_tail_has_arrived() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    builder.push(packet(10, 2400, false, &[0x62, 0x01, 0x93, 0xaa]));
    assert!(builder.pop().is_none());
    builder.push(packet(12, 2400, true, &[0x62, 0x01, 0x53, 0xcc]));
    assert!(builder.pop().is_none(), "A marker cannot bridge a missing fragment");
    builder.push(packet(11, 2400, false, &[0x62, 0x01, 0x13, 0xbb]));
    let sample = builder.pop().unwrap();
    assert_eq!(sample.data.as_ref(), &[0, 0, 0, 1, 0x26, 0x01, 0xaa, 0xbb, 0xcc]);
    assert_eq!(sample.prev_dropped_packets, 0);
    assert!(builder.pop().is_none());
}

#[test]
fn unmarked_picture_is_not_released_early() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    builder.push(packet(10, 2400, false, &[0x26, 0x01, 0xaa]));
    assert!(builder.pop().is_none());
    builder.push(packet(12, 3200, true, &[0x26, 0x01, 0xcc]));
    assert!(builder.pop().is_none(), "Missing tail cannot be bypassed by a later picture");
    builder.push(packet(11, 2400, false, &[0x02, 0x01, 0xbb]));
    // Existing timestamp-boundary completion remains valid once the gap is repaired.
    assert_eq!(builder.pop().unwrap().packet_timestamp, 2400);
}

#[test]
fn orphan_fragment_tail_is_not_released_as_a_picture() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    builder.push(packet(10, 2400, true, &[0x62, 0x01, 0x53, 0xaa]));
    assert!(builder.pop().is_none());
}

#[test]
fn immediate_release_handles_sequence_and_timestamp_wrap() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    let timestamp = u32::MAX - 399;
    builder.push(packet(u16::MAX, timestamp, false, &[0x62, 0x01, 0x93, 0xaa]));
    assert!(builder.pop().is_none());
    builder.push(packet(0, timestamp, true, &[0x62, 0x01, 0x53, 0xbb]));
    let sample = builder.pop().unwrap();
    assert_eq!(sample.packet_timestamp, timestamp);
    assert_eq!(sample.duration, Duration::ZERO);
    assert_eq!(sample.prev_dropped_packets, 0);
    builder.push(packet(1, 400, true, &[0x26, 0x01, 0xcc]));
    assert_eq!(builder.pop().unwrap().packet_timestamp, 400);
}

#[test]
fn immediate_release_keeps_known_next_timestamp_duration() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    builder.push(packet(10, 2400, true, &[0x26, 0x01, 0xaa]));
    builder.push(packet(11, 3200, true, &[0x26, 0x01, 0xbb]));
    assert_eq!(builder.pop().unwrap().duration,
        Duration::from_secs_f64(800.0 / 24_000.0));
}

#[test]
fn released_picture_duplicates_do_not_rewind_or_replay() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    let first = packet(u16::MAX, 2400, true, &[0x26, 0x01, 0xaa]);
    builder.push(first.clone());
    assert_eq!(builder.pop().unwrap().packet_timestamp, 2400);
    builder.push(first.clone());
    assert!(builder.pop().is_none(), "A retransmission of a released picture is stale");
    builder.push(packet(0, 3200, false, &[0x62, 0x01, 0x93, 0xbb]));
    builder.push(first);
    assert!(builder.pop().is_none());
    builder.push(packet(1, 3200, true, &[0x62, 0x01, 0x53, 0xcc]));
    let next = builder.pop().unwrap();
    assert_eq!(next.packet_timestamp, 3200);
    assert_eq!(next.prev_dropped_packets, 0);
    assert!(builder.pop().is_none());
}

#[test]
fn consecutive_multi_packet_pictures_release_without_residual_fragments() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    for picture in 0..500u16 {
        let sequence = 65000u16.wrapping_add(picture.wrapping_mul(3));
        let timestamp = u32::from(picture) * 800;
        builder.push(packet(sequence, timestamp, false, &[0x62, 0x01, 0x93, 0xaa]));
        assert!(builder.pop().is_none());
        builder.push(packet(sequence.wrapping_add(1), timestamp, false, &[0x62, 0x01, 0x13, 0xbb]));
        assert!(builder.pop().is_none());
        builder.push(packet(sequence.wrapping_add(2), timestamp, true, &[0x62, 0x01, 0x53, 0xcc]));
        let sample = builder.pop().expect("Every complete picture must release on its own tail");
        assert_eq!(sample.packet_timestamp, timestamp);
        assert_eq!(sample.data.as_ref(), &[0, 0, 0, 1, 0x26, 0x01, 0xaa, 0xbb, 0xcc]);
        assert_eq!(sample.prev_dropped_packets, 0);
    }
    assert_eq!(builder.flush(), (None, false));
}

#[test]
fn irreparable_gap_is_reported_and_never_emitted_as_complete() {
    let mut builder = SampleBuilder::new(3, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    builder.push(packet(10, 2400, false, &[0x62, 0x01, 0x93, 0xaa]));
    builder.push(packet(12, 2400, true, &[0x62, 0x01, 0x53, 0xcc]));
    assert!(builder.pop().is_none());
    let mut recovered = Vec::new();
    for sequence in 13..20 {
        builder.push(packet(sequence, u32::from(sequence - 9) * 800,
            true, &[0x26, 0x01, 0xdd]));
        while let Some(sample) = builder.pop() {
            assert_ne!(sample.packet_timestamp, 2400, "Never release the incomplete picture");
            assert_eq!(sample.data.as_ref(), &[0, 0, 0, 1, 0x26, 0x01, 0xdd]);
            recovered.push(sample);
        }
    }
    assert!(!recovered.is_empty(), "Valid following pictures must survive buffer purging");
    assert!(recovered[0].prev_dropped_packets > 0,
        "Lost fragments must retain loss accounting");
}

#[test]
fn next_picture_tail_cannot_hide_missing_leading_nals() {
    let mut builder = SampleBuilder::new(200, H265Packet::default(), 24_000)
        .with_immediate_partition_release();
    builder.push(packet(10, 2400, true, &[0x26, 0x01, 0xaa]));
    assert!(builder.pop().is_some());
    // A standalone NAL is a valid depacketizer partition head, but sequence 11
    // is still required: this marker is the SECOND NAL in the next picture.
    builder.push(packet(12, 3200, true, &[0x02, 0x01, 0xcc]));
    assert!(builder.pop().is_none(), "Do not mistake a leading gap for a complete picture");
    builder.push(packet(11, 3200, false, &[0x02, 0x01, 0xbb]));
    let sample = builder.pop().unwrap();
    assert_eq!(sample.packet_timestamp, 3200);
    assert_eq!(sample.prev_dropped_packets, 0);
    assert_eq!(sample.data.as_ref(),
        &[0, 0, 0, 1, 0x02, 0x01, 0xbb, 0, 0, 0, 1, 0x02, 0x01, 0xcc]);
}

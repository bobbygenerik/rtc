use super::*;
use shared::marshal::*;

use bytes::Bytes;
use lazy_static::lazy_static;

struct RTPTestCase {
    sequence_number: u16,
    encrypted: Bytes,
}

lazy_static! {
    static ref RTP_TEST_CASE_DECRYPTED: Bytes = Bytes::from_static(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    static ref RTP_TEST_CASES: Vec<RTPTestCase> = vec![
        RTPTestCase {
            sequence_number: 5000,
            encrypted: Bytes::from_static(&[
                0x6d, 0xd3, 0x7e, 0xd5, 0x99, 0xb7, 0x2d, 0x28, 0xb1, 0xf3, 0xa1, 0xf0, 0xc, 0xfb,
                0xfd, 0x8
            ]),
        },
        RTPTestCase {
            sequence_number: 5001,
            encrypted: Bytes::from_static(&[
                0xda, 0x47, 0xb, 0x2a, 0x74, 0x53, 0x65, 0xbd, 0x2f, 0xeb, 0xdc, 0x4b, 0x6d, 0x23,
                0xf3, 0xde
            ]),
        },
        RTPTestCase {
            sequence_number: 5002,
            encrypted: Bytes::from_static(&[
                0x6e, 0xa7, 0x69, 0x8d, 0x24, 0x6d, 0xdc, 0xbf, 0xec, 0x2, 0x1c, 0xd1, 0x60, 0x76,
                0xc1, 0x0e
            ]),
        },
        RTPTestCase {
            sequence_number: 5003,
            encrypted: Bytes::from_static(&[
                0x24, 0x7e, 0x96, 0xc8, 0x7d, 0x33, 0xa2, 0x92, 0x8d, 0x13, 0x8d, 0xe0, 0x76, 0x9f,
                0x08, 0xdc
            ]),
        },
        RTPTestCase {
            sequence_number: 5004,
            encrypted: Bytes::from_static(&[
                0x75, 0x43, 0x28, 0xe4, 0x3a, 0x77, 0x59, 0x9b, 0x2e, 0xdf, 0x7b, 0x12, 0x68, 0x0b,
                0x57, 0x49
            ]),
        },
        RTPTestCase{
            sequence_number: 65535, // upper boundary
            encrypted: Bytes::from_static(&[
                0xaf, 0xf7, 0xc2, 0x70, 0x37, 0x20, 0x83, 0x9c, 0x2c, 0x63, 0x85, 0x15, 0x0e, 0x44,
                0xca, 0x36
            ]),
        },
    ];
}

fn build_test_context() -> Result<Context> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);

    Context::new(
        &master_key,
        &master_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
    )
}

#[test]
fn test_rtp_invalid_auth() -> Result<()> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let invalid_salt = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut encrypt_context = build_test_context()?;
    let mut invalid_context = Context::new(
        &master_key,
        &invalid_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
    )?;

    for test_case in &*RTP_TEST_CASES {
        let pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };

        let pkt_raw = pkt.marshal()?;
        let out = encrypt_context.encrypt_rtp(&pkt_raw)?;

        let result = invalid_context.decrypt_rtp(&out);
        assert!(
            result.is_err(),
            "Managed to decrypt with incorrect salt for packet with SeqNum: {}",
            test_case.sequence_number
        );
    }

    Ok(())
}

#[test]
fn test_rtp_lifecyle() -> Result<()> {
    let mut encrypt_context = build_test_context()?;
    let mut decrypt_context = build_test_context()?;
    let auth_tag_len = ProtectionProfile::Aes128CmHmacSha1_80.rtp_auth_tag_len();

    for test_case in RTP_TEST_CASES.iter() {
        let decrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };

        let decrypted_raw = decrypted_pkt.marshal()?;

        let encrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: test_case.encrypted.clone(),
        };

        let encrypted_raw = encrypted_pkt.marshal()?;
        let actual_encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;
        assert_eq!(
            actual_encrypted, encrypted_raw,
            "RTP packet with SeqNum invalid encryption: {}",
            test_case.sequence_number
        );

        let actual_decrypted = decrypt_context.decrypt_rtp(&encrypted_raw)?;
        assert_ne!(
            encrypted_raw[..encrypted_raw.len() - auth_tag_len].to_vec(),
            actual_decrypted,
            "DecryptRTP improperly encrypted in place"
        );

        assert_eq!(
            actual_decrypted, decrypted_raw,
            "RTP packet with SeqNum invalid decryption: {}",
            test_case.sequence_number,
        )
    }

    Ok(())
}

#[test]
fn test_rtp_sha2_mki_lifecycle() -> Result<()> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);

    for profile in [
        ProtectionProfile::Aes128CmHmacSha2mki_80,
        ProtectionProfile::Aes128CmHmacSha2mki_32,
    ] {
        let mut encrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;
        let mut decrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;
        let auth_tag_len = profile.rtp_auth_tag_len();
        let mki_len = profile.mki_len();

        let decrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: 5000,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };
        let decrypted_raw = decrypted_pkt.marshal()?;
        let encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;

        assert_eq!(
            encrypted.len(),
            decrypted_raw.len() + auth_tag_len + mki_len
        );
        assert_eq!(
            &encrypted[encrypted.len() - auth_tag_len - mki_len..encrypted.len() - auth_tag_len],
            &[0x00, 0x10]
        );
        assert_eq!(decrypt_context.decrypt_rtp(&encrypted)?, decrypted_raw);

        let mut with_changed_mki = encrypted.clone();
        let mki_offset = with_changed_mki.len() - auth_tag_len - mki_len;
        with_changed_mki[mki_offset..mki_offset + mki_len].copy_from_slice(&[0xab, 0xcd]);
        assert_eq!(
            decrypt_context.decrypt_rtp(&with_changed_mki)?,
            decrypted_raw
        );

        let mut with_changed_auth = encrypted.clone();
        let auth_offset = with_changed_auth.len() - auth_tag_len;
        with_changed_auth[auth_offset] ^= 0xff;
        assert!(decrypt_context.decrypt_rtp(&with_changed_auth).is_err());

        let trailer_data_len = 4;
        let decrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: 0x5080,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };
        let decrypted_raw = decrypted_pkt.marshal()?;
        let encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;

        assert_eq!(
            encrypted.len(),
            decrypted_raw.len() + auth_tag_len + mki_len + trailer_data_len
        );
        let trailer_offset = encrypted.len() - auth_tag_len - trailer_data_len - mki_len;
        assert_eq!(
            &encrypted[trailer_offset..trailer_offset + mki_len],
            &[0x00, 0x10]
        );
        assert_eq!(decrypt_context.decrypt_rtp(&encrypted)?, decrypted_raw);

        if trailer_data_len > 0 {
            assert_eq!(
                &encrypted[trailer_offset + mki_len..trailer_offset + mki_len + trailer_data_len],
                &[0x00, 0x00, 0x00, 0x20]
            );

            let mut with_changed_trailer_data = encrypted.clone();
            let data_offset = trailer_offset + mki_len;
            with_changed_trailer_data[data_offset..data_offset + trailer_data_len]
                .copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
            assert!(decrypt_context.decrypt_rtp(&with_changed_trailer_data).is_err());
            assert_eq!(decrypt_context.get_roc(0), Some(0));
        }
    }

    Ok(())
}

#[test]
fn test_rtp_mki_no_auth_lifecycle() -> Result<()> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);
    let profile = ProtectionProfile::Aes128CmMkiNoAuth;
    let mut encrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;
    let mut decrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;

    for sequence_number in [5000, 0x5080] {
        let decrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };
        let decrypted_raw = decrypted_pkt.marshal()?;
        let encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;

        assert_eq!(encrypted.len(), decrypted_raw.len() + 6);
        assert_eq!(&encrypted[encrypted.len() - 6..], &[0x00, 0x10, 0x00, 0x00, 0x00, 0x20]);
        assert_eq!(decrypt_context.decrypt_rtp(&encrypted)?, decrypted_raw);
    }

    let ssrc = 0x12345678;
    let roc = 1;
    let mut encrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;
    let mut decrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;
    let before_rollover = rtp::Packet {
        header: rtp::Header {
            sequence_number: u16::MAX,
            ssrc,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let before_rollover = encrypt_context.encrypt_rtp(&before_rollover.marshal()?)?;
    assert_eq!(
        &before_rollover[before_rollover.len() - 6..],
        &[0x00, 0x10, 0x00, 0x00, 0x00, 0x20]
    );

    let rollover = rtp::Packet {
        header: rtp::Header {
            sequence_number: 0,
            ssrc,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let rollover = encrypt_context.encrypt_rtp(&rollover.marshal()?)?;
    assert_eq!(
        &rollover[rollover.len() - 6..],
        &[0x00, 0x10, 0x00, 0x00, 0x01, 0x20]
    );

    let decrypted_pkt = rtp::Packet {
        header: rtp::Header {
            sequence_number: 3704,
            ssrc,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let decrypted_raw = decrypted_pkt.marshal()?;
    let encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;

    assert_eq!(
        &encrypted[encrypted.len() - 6..],
        &[0x00, 0x10, 0x00, 0x00, 0x01, 0x20]
    );
    assert_eq!(decrypt_context.decrypt_rtp(&encrypted)?, decrypted_raw);
    assert_eq!(decrypt_context.get_roc(ssrc), Some(roc));

    Ok(())
}

#[test]
fn test_rtp_trailer_rollover_counter_lifecycle() -> Result<()> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);
    let ssrc = 0x12345678;
    let roc = 0x123456;

    for (profile, sequence_number) in [
        (ProtectionProfile::Aes128CmMkiNoAuth, 5000),
        (ProtectionProfile::Aes128CmHmacSha2mki_80, 0x5080),
        (ProtectionProfile::Aes128CmHmacSha2mki_32, 0x5080),
    ] {
        let mut encrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;
        let mut decrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;
        encrypt_context.set_roc(ssrc, roc);

        let decrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number,
                ssrc,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };
        let decrypted_raw = decrypted_pkt.marshal()?;
        let encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;
        let auth_tag_len = profile.rtp_auth_tag_len();
        let trailer_offset = encrypted.len() - auth_tag_len - 4;

        assert_eq!(
            &encrypted[trailer_offset..trailer_offset + 4],
            &[0x12, 0x34, 0x56, 0x20]
        );
        assert_eq!(decrypt_context.decrypt_rtp(&encrypted)?, decrypted_raw);
        assert_eq!(decrypt_context.get_roc(ssrc), Some(roc));
    }

    Ok(())
}

#[test]
fn test_rtp_trailer_rollover_counter_resynchronizes_existing_state() -> Result<()> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);
    let profile = ProtectionProfile::Aes128CmHmacSha2mki_32;
    let ssrc = 0x12345678;
    let mut decrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;

    let mut old_encrypt_context = Context::new(&master_key, &master_salt, profile, None, None)?;
    old_encrypt_context.set_roc(ssrc, 1);
    let old_packet = rtp::Packet {
        header: rtp::Header {
            sequence_number: 0x5080,
            ssrc,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let old_plaintext = old_packet.marshal()?;
    let old_encrypted = old_encrypt_context.encrypt_rtp(&old_plaintext)?;
    assert_eq!(decrypt_context.decrypt_rtp(&old_encrypted)?, old_plaintext);
    assert_eq!(decrypt_context.get_roc(ssrc), Some(1));

    let mut restarted_encrypt_context =
        Context::new(&master_key, &master_salt, profile, None, None)?;
    let restarted_packet = rtp::Packet {
        header: rtp::Header {
            sequence_number: 0x5100,
            ssrc,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let restarted_plaintext = restarted_packet.marshal()?;
    let restarted_encrypted = restarted_encrypt_context.encrypt_rtp(&restarted_plaintext)?;
    let mut invalid_restarted_encrypted = restarted_encrypted.clone();
    let trailer_offset = invalid_restarted_encrypted.len() - profile.rtp_auth_tag_len() - 4;
    invalid_restarted_encrypted[trailer_offset..trailer_offset + 3]
        .copy_from_slice(&[0x00, 0x00, 0x02]);
    assert!(decrypt_context.decrypt_rtp(&invalid_restarted_encrypted).is_err());
    assert_eq!(decrypt_context.get_roc(ssrc), Some(1));

    assert_eq!(
        decrypt_context.decrypt_rtp(&restarted_encrypted)?,
        restarted_plaintext
    );
    assert_eq!(decrypt_context.get_roc(ssrc), Some(0));

    let following_packet = rtp::Packet {
        header: rtp::Header {
            sequence_number: 0x5101,
            ssrc,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let following_plaintext = following_packet.marshal()?;
    let following_encrypted = restarted_encrypt_context.encrypt_rtp(&following_plaintext)?;
    assert_eq!(
        decrypt_context.decrypt_rtp(&following_encrypted)?,
        following_plaintext
    );
    assert_eq!(decrypt_context.get_roc(ssrc), Some(0));

    Ok(())
}

#[test]
fn test_replace_shared_cipher_preserves_rollover_state() -> Result<()> {
    let old_master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let old_master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);
    let new_master_key = [0x11; 16];
    let new_master_salt = [0x22; 14];
    let profile = ProtectionProfile::Aes128CmHmacSha2mki_80;
    let ssrc = 0x12345678;

    let old_cipher = new_cipher(&old_master_key, &old_master_salt, profile)?;
    let mut encrypt_context = Context::new_with_cipher(old_cipher.clone(), None, None);
    let mut decrypt_context = Context::new_with_cipher(old_cipher.clone(), None, None);

    let late_packet = rtp::Packet {
        header: rtp::Header {
            sequence_number: u16::MAX - 1,
            ssrc,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let late_plaintext = late_packet.marshal()?;
    let late_encrypted = encrypt_context.encrypt_rtp(&late_plaintext)?;

    let before_rollover = rtp::Packet {
        header: rtp::Header {
            sequence_number: u16::MAX,
            ssrc,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let before_rollover_plaintext = before_rollover.marshal()?;
    let before_rollover_encrypted = encrypt_context.encrypt_rtp(&before_rollover_plaintext)?;
    assert_eq!(
        decrypt_context.decrypt_rtp(&before_rollover_encrypted)?,
        before_rollover_plaintext
    );

    let new_cipher = new_cipher(&new_master_key, &new_master_salt, profile)?;
    let old_encrypt_cipher = encrypt_context.replace_cipher(new_cipher.clone());
    let old_decrypt_cipher = decrypt_context.replace_cipher(new_cipher);
    assert!(Arc::ptr_eq(&old_cipher, &old_encrypt_cipher));
    assert!(Arc::ptr_eq(&old_cipher, &old_decrypt_cipher));

    let after_rollover = rtp::Packet {
        header: rtp::Header {
            sequence_number: 1,
            ssrc,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let after_rollover_plaintext = after_rollover.marshal()?;
    let after_rollover_encrypted = encrypt_context.encrypt_rtp(&after_rollover_plaintext)?;
    assert_eq!(
        decrypt_context.decrypt_rtp(&after_rollover_encrypted)?,
        after_rollover_plaintext
    );
    assert_eq!(decrypt_context.get_roc(ssrc), Some(1));

    decrypt_context.replace_cipher(old_decrypt_cipher);
    assert_eq!(decrypt_context.decrypt_rtp(&late_encrypted)?, late_plaintext);

    Ok(())
}

//TODO: BenchmarkEncryptRTP
//TODO: BenchmarkEncryptRTPInPlace
//TODO: BenchmarkDecryptRTP

mod cipher_aead_aes_gcm;
mod cipher_aes_cm_hmac_sha1;

use bytes::BytesMut;
use std::sync::Arc;

use aes::{Aes128, Aes256};
use shared::error::{Error, Result};

use crate::protection_profile::ProtectionProfile;
use cipher_aead_aes_gcm::CipherAeadAesGcm;
use cipher_aes_cm_hmac_sha1::CipherAesCmHmacSha1;

type Kdf = fn(u8, &[u8], &[u8], usize, usize) -> Result<Vec<u8>>;

///NOTE: Auth tag and AEAD auth tag are placed at the different position in SRTCP
///
///In non-AEAD cipher, the authentication tag is placed *after* the ESRTCP word
///(Encrypted-flag and SRTCP index).
///
///> AES_128_CM_HMAC_SHA1_80
///> | RTCP Header | Encrypted payload |E| SRTCP Index | Auth tag |
///>                                   ^               |----------|
///>                                   |                ^
///>                                   |                authTagLen=10
///>                                   aeadAuthTagLen=0
///
///In AEAD cipher, the AEAD authentication tag is embedded in the ciphertext.
///It is *before* the ESRTCP word (Encrypted-flag and SRTCP index).
///
///> AEAD_AES_128_GCM
///> | RTCP Header | Encrypted payload | AEAD auth tag |E| SRTCP Index |
///>                                   |---------------|               ^
///>                                    ^                              authTagLen=0
///>                                    aeadAuthTagLen=16
///
///See https://tools.ietf.org/html/rfc7714 for the full specifications.
///
/// Cipher represents a implementation of one
/// of the SRTP Specific ciphers.
pub trait Cipher: Send + Sync {
    /// Get RTP authenticated tag length.
    fn rtp_auth_tag_len(&self) -> usize;

    /// Get RTCP authenticated tag length.
    fn rtcp_auth_tag_len(&self) -> usize;

    /// Get AEAD auth key length of the cipher.
    fn aead_auth_tag_len(&self) -> usize;

    /// Retrieved RTCP index.
    fn get_rtcp_index(&self, input: &[u8]) -> usize;

    /// Retrieved RTP rollover counter when carried by the protection profile.
    fn get_rtp_rollover_counter(
        &self,
        _input: &[u8],
        _sequence_number: u16,
    ) -> Option<u32> {
        None
    }

    /// Encrypt RTP payload.
    fn encrypt_rtp(&self, payload: &[u8], header: &rtp::Header, roc: u32) -> Result<BytesMut>;

    /// Decrypt RTP payload.
    fn decrypt_rtp(&self, payload: &[u8], header: &rtp::Header, roc: u32) -> Result<BytesMut>;

    /// Encrypt RTCP payload.
    fn encrypt_rtcp(&self, payload: &[u8], srtcp_index: usize, ssrc: u32) -> Result<BytesMut>;

    /// Decrypt RTCP payload.
    fn decrypt_rtcp(&self, payload: &[u8], srtcp_index: usize, ssrc: u32) -> Result<BytesMut>;
}

/// Create immutable SRTP cipher material that can be shared by multiple
/// contexts and installed without resetting their packet-index state.
pub fn new_cipher(
    master_key: &[u8],
    master_salt: &[u8],
    profile: ProtectionProfile,
) -> Result<Arc<dyn Cipher>> {
    let key_len = profile.key_len();
    let salt_len = profile.salt_len();

    if master_key.len() != key_len {
        return Err(Error::SrtpMasterKeyLength(key_len, master_key.len()));
    } else if master_salt.len() != salt_len {
        return Err(Error::SrtpSaltLength(salt_len, master_salt.len()));
    }

    match profile {
        ProtectionProfile::Aes128CmHmacSha1_32
        | ProtectionProfile::Aes128CmHmacSha1_80
        | ProtectionProfile::Aes128CmHmacSha2mki_32
        | ProtectionProfile::Aes128CmHmacSha2mki_80
        | ProtectionProfile::Aes128CmMkiNoAuth
        | ProtectionProfile::Aes256CmHmacSha1_80
        | ProtectionProfile::Aes256CmHmacSha1_32 => Ok(Arc::new(CipherAesCmHmacSha1::new(
            profile,
            master_key,
            master_salt,
        )?)),

        ProtectionProfile::AeadAes128Gcm => Ok(Arc::new(CipherAeadAesGcm::<Aes128>::new(
            profile,
            master_key,
            master_salt,
        )?)),

        ProtectionProfile::AeadAes256Gcm => Ok(Arc::new(CipherAeadAesGcm::<Aes256>::new(
            profile,
            master_key,
            master_salt,
        )?)),
    }
}

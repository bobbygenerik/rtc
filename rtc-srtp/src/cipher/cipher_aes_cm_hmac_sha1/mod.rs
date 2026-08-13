use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

use super::{Cipher, Kdf};
use crate::key_derivation::*;
use crate::protection_profile::*;
use shared::error::{Error, Result};

#[cfg(not(feature = "openssl"))]
mod ctrcipher;

#[cfg(feature = "openssl")]
mod opensslcipher;

#[cfg(not(feature = "openssl"))]
pub(crate) use ctrcipher::CipherAesCmHmacSha1;

#[cfg(feature = "openssl")]
pub(crate) use opensslcipher::CipherAesCmHmacSha1;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
enum Auth {
    Sha1(HmacSha1),
    Sha256(HmacSha256),
}

impl Auth {
    fn new(profile: ProtectionProfile, key: &[u8]) -> Result<Self> {
        match profile {
            ProtectionProfile::Aes128CmHmacSha2mki_80
            | ProtectionProfile::Aes128CmHmacSha2mki_32 => HmacSha256::new_from_slice(key)
                .map(Auth::Sha256)
                .map_err(|e| Error::Other(e.to_string())),
            _ => HmacSha1::new_from_slice(key)
                .map(Auth::Sha1)
                .map_err(|e| Error::Other(e.to_string())),
        }
    }

    fn sign(&self, chunks: &[&[u8]]) -> [u8; 32] {
        let mut out = [0; 32];
        match self {
            Auth::Sha1(auth) => {
                let mut signer = auth.clone();
                for chunk in chunks {
                    signer.update(chunk);
                }
                out[..20].copy_from_slice(&signer.finalize().into_bytes());
            }
            Auth::Sha256(auth) => {
                let mut signer = auth.clone();
                for chunk in chunks {
                    signer.update(chunk);
                }
                out.copy_from_slice(&signer.finalize().into_bytes());
            }
        }
        out
    }
}

pub const CIPHER_AES_CM_HMAC_SHA1AUTH_TAG_LEN: usize = 10;
const RTP_TRAILER_DATA_LEN: usize = 4;
pub(super) const RTP_MKI: [u8; 2] = [0x00, 0x10];
const RTP_TRAILER_DATA_FLAGS: u8 = 0x20;

fn rtp_trailer_data_len(profile: ProtectionProfile, sequence_number: u16) -> usize {
    if matches!(profile, ProtectionProfile::Aes128CmMkiNoAuth)
        || matches!(profile, ProtectionProfile::Aes128CmHmacSha2mki_80 | ProtectionProfile::Aes128CmHmacSha2mki_32) && sequence_number & 0x7f == 0 {
        RTP_TRAILER_DATA_LEN
    } else {
        0
    }
}

fn rtp_trailer_data(
    profile: ProtectionProfile,
    sequence_number: u16,
    roc: u32,
) -> Option<[u8; RTP_TRAILER_DATA_LEN]> {
    if rtp_trailer_data_len(profile, sequence_number) == 0 {
        return None;
    }

    Some([
        (roc >> 16) as u8,
        (roc >> 8) as u8,
        roc as u8,
        RTP_TRAILER_DATA_FLAGS,
    ])
}

fn rtp_rollover_counter(
    profile: ProtectionProfile,
    input: &[u8],
    auth_tag_len: usize,
    sequence_number: u16,
) -> Option<u32> {
    if rtp_trailer_data_len(profile, sequence_number) == 0
        || input.len() < auth_tag_len + profile.mki_len() + RTP_TRAILER_DATA_LEN
    {
        return None;
    }

    let trailer_offset = input.len() - auth_tag_len - RTP_TRAILER_DATA_LEN;
    let trailer = &input[trailer_offset..trailer_offset + RTP_TRAILER_DATA_LEN];
    if trailer[3] & RTP_TRAILER_DATA_FLAGS == 0 {
        return None;
    }

    Some(((trailer[0] as u32) << 16) | ((trailer[1] as u32) << 8) | trailer[2] as u32)
}

pub(crate) struct CipherInner {
    profile: ProtectionProfile,
    srtp_session_salt: Vec<u8>,
    srtp_session_auth: Auth,
    srtcp_session_salt: Vec<u8>,
    srtcp_session_auth: Auth,
}

impl CipherInner {
    pub fn new(
        profile: ProtectionProfile,
        kdf: Kdf,
        master_key: &[u8],
        master_salt: &[u8],
    ) -> Result<Self> {
        let srtp_session_salt = kdf(
            LABEL_SRTP_SALT,
            master_key,
            master_salt,
            0,
            master_salt.len(),
        )?;
        let srtcp_session_salt = kdf(
            LABEL_SRTCP_SALT,
            master_key,
            master_salt,
            0,
            master_salt.len(),
        )?;

        let auth_key_len = profile.auth_key_len();
        let srtp_session_auth_tag = kdf(
            LABEL_SRTP_AUTHENTICATION_TAG,
            master_key,
            master_salt,
            0,
            auth_key_len,
        )?;
        let srtcp_session_auth_tag = kdf(
            LABEL_SRTCP_AUTHENTICATION_TAG,
            master_key,
            master_salt,
            0,
            auth_key_len,
        )?;

        let srtp_session_auth = Auth::new(profile, &srtp_session_auth_tag)?;
        let srtcp_session_auth = Auth::new(profile, &srtcp_session_auth_tag)?;

        Ok(Self {
            profile,
            srtp_session_salt,
            srtp_session_auth,
            srtcp_session_salt,
            srtcp_session_auth,
        })
    }

    /// https://tools.ietf.org/html/rfc3711#section-4.2
    /// In the case of SRTP, M SHALL consist of the Authenticated
    /// Portion of the packet (as specified in Figure 1) concatenated with
    /// the roc, M = Authenticated Portion || roc;
    ///
    /// The pre-defined authentication transform for SRTP is HMAC-SHA1
    /// [RFC2104].  With HMAC-SHA1, the SRTP_PREFIX_LENGTH (Figure 3) SHALL
    /// be 0.  For SRTP (respectively SRTCP), the HMAC SHALL be applied to
    /// the session authentication key and M as specified above, i.e.,
    /// HMAC(k_a, M).  The HMAC output SHALL then be truncated to the n_tag
    /// left-most bits.
    /// - Authenticated portion of the packet is everything BEFORE MKI
    /// - k_a is the session message authentication key
    /// - n_tag is the bit-length of the output authentication tag
    fn generate_srtp_auth_tag(&self, buf: &[u8], roc: u32) -> [u8; 32] {
        self.srtp_session_auth.sign(&[buf, &roc.to_be_bytes()])
    }

    /// https://tools.ietf.org/html/rfc3711#section-4.2
    ///
    /// The pre-defined authentication transform for SRTP is HMAC-SHA1
    /// [RFC2104].  With HMAC-SHA1, the SRTP_PREFIX_LENGTH (Figure 3) SHALL
    /// be 0.  For SRTP (respectively SRTCP), the HMAC SHALL be applied to
    /// the session authentication key and M as specified above, i.e.,
    /// HMAC(k_a, M).  The HMAC output SHALL then be truncated to the n_tag
    /// left-most bits.
    /// - Authenticated portion of the packet is everything BEFORE MKI
    /// - k_a is the session message authentication key
    /// - n_tag is the bit-length of the output authentication tag
    fn generate_srtcp_auth_tag(&self, buf: &[u8]) -> [u8; 32] {
        self.srtcp_session_auth.sign(&[buf])
    }

    fn get_rtcp_index(&self, input: &[u8]) -> usize {
        let tail_offset = input.len()
            - (self.profile.mki_len() + self.profile.rtcp_auth_tag_len() + SRTCP_INDEX_SIZE);
        (BigEndian::read_u32(&input[tail_offset..tail_offset + SRTCP_INDEX_SIZE]) & !(1 << 31))
            as usize
    }
}

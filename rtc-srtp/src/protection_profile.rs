/// ProtectionProfile specifies Cipher and AuthTag details, similar to TLS cipher suite
#[derive(Default, Debug, Clone, Copy)]
#[repr(u8)]
pub enum ProtectionProfile {
    #[default]
    Aes128CmHmacSha1_80 = 0x0001,
    Aes128CmHmacSha1_32 = 0x0002,
    Aes256CmHmacSha1_80 = 0x0003,
    Aes256CmHmacSha1_32 = 0x0004,
    AeadAes128Gcm = 0x0007,
    AeadAes256Gcm = 0x0008,
    #[allow(non_camel_case_types)]
    Aes128CmHmacSha2mki_80 = 0x0009,
    #[allow(non_camel_case_types)]
    Aes128CmHmacSha2mki_32 = 0x00010,
    Aes128CmMkiNoAuth = 0x0011,
}

impl ProtectionProfile {
    pub fn key_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes128CmHmacSha2mki_32
            | ProtectionProfile::Aes128CmHmacSha2mki_80
            | ProtectionProfile::Aes128CmMkiNoAuth
            | ProtectionProfile::AeadAes128Gcm => 16,
            ProtectionProfile::Aes256CmHmacSha1_32 | ProtectionProfile::Aes256CmHmacSha1_80 => 32,
            ProtectionProfile::AeadAes256Gcm => 32,
        }
    }

    pub fn salt_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes128CmHmacSha2mki_32
            | ProtectionProfile::Aes128CmHmacSha2mki_80
            | ProtectionProfile::Aes128CmMkiNoAuth
            | ProtectionProfile::Aes256CmHmacSha1_32
            | ProtectionProfile::Aes256CmHmacSha1_80 => 14,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 12,
        }
    }

    pub fn rtp_auth_tag_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes128CmHmacSha2mki_80
            | ProtectionProfile::Aes256CmHmacSha1_80 => 10,
            ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes128CmHmacSha2mki_32
            | ProtectionProfile::Aes256CmHmacSha1_32 => 4,
            ProtectionProfile::Aes128CmMkiNoAuth
            | ProtectionProfile::AeadAes128Gcm
            | ProtectionProfile::AeadAes256Gcm => 0,
        }
    }

    pub fn rtcp_auth_tag_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes128CmHmacSha2mki_80
            | ProtectionProfile::Aes128CmHmacSha2mki_32
            | ProtectionProfile::Aes256CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_32 => 10,
            ProtectionProfile::Aes128CmMkiNoAuth
            | ProtectionProfile::AeadAes128Gcm
            | ProtectionProfile::AeadAes256Gcm => 0,
        }
    }

    pub fn aead_auth_tag_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes128CmHmacSha2mki_80
            | ProtectionProfile::Aes128CmHmacSha2mki_32
            | ProtectionProfile::Aes128CmMkiNoAuth
            | ProtectionProfile::Aes256CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_32 => 0,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 16,
        }
    }

    pub fn auth_key_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes128CmMkiNoAuth
            | ProtectionProfile::Aes256CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_32 => 20,
            ProtectionProfile::Aes128CmHmacSha2mki_80
            | ProtectionProfile::Aes128CmHmacSha2mki_32 => 32,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 0,
        }
    }

    pub fn mki_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha2mki_80
            | ProtectionProfile::Aes128CmHmacSha2mki_32
            | ProtectionProfile::Aes128CmMkiNoAuth => 2,
            _ => 0,
        }
    }
}

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString};

#[cfg(feature = "std")]
use std::string::{String, ToString};

macro_rules! define_identifier_trait {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        pub trait $name {
            /// Return the Botan interface string for this identifier.
            fn botan_name(&self) -> String;
        }

        impl $name for str {
            fn botan_name(&self) -> String {
                self.to_string()
            }
        }

        impl $name for String {
            fn botan_name(&self) -> String {
                self.clone()
            }
        }

        impl<T: $name + ?Sized> $name for &T {
            fn botan_name(&self) -> String {
                (*self).botan_name()
            }
        }
    };
}

define_identifier_trait!(
    /// A type that identifies a Botan hash function.
    HashAlgorithmIdentifier
);

define_identifier_trait!(
    /// A type that identifies a Botan block cipher.
    BlockCipherAlgorithmIdentifier
);

define_identifier_trait!(
    /// A type that identifies a Botan cipher or cipher mode.
    CipherAlgorithmIdentifier
);

define_identifier_trait!(
    /// A type that identifies a Botan message authentication code.
    MacAlgorithmIdentifier
);

define_identifier_trait!(
    /// A type that identifies a Botan key derivation function.
    KdfAlgorithmIdentifier
);

define_identifier_trait!(
    /// A type that identifies a Botan password hashing or password based KDF algorithm.
    PasswordHashAlgorithmIdentifier
);

define_identifier_trait!(
    /// A type that identifies the KDF used to encrypt a PKCS #8 private key.
    Pkcs8KdfIdentifier
);

define_identifier_trait!(
    /// A type that identifies a Botan public key algorithm.
    PublicKeyAlgorithmIdentifier
);

define_identifier_trait!(
    /// A type that identifies parameters for Botan private key generation,
    /// such as an elliptic curve group or a post-quantum parameter set.
    KeyGenParamsIdentifier
);

define_identifier_trait!(
    /// A type that identifies the parameters of a Botan public key encryption scheme.
    EncryptionParamsIdentifier
);

define_identifier_trait!(
    /// A type that identifies the parameters of a Botan public key signature scheme.
    SignatureParamsIdentifier
);

define_identifier_trait!(
    /// A type that identifies a Botan random number generator.
    RngTypeIdentifier
);

/// Hash functions accepted by Botan's hash interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// Any Botan hash identifier not modeled by this enum, for example
    /// `Truncated(SHA-256,16)` or `Parallel(SHA-256,SHA-512)`.
    Arbitrary(String),
    /// Ascon-Hash256.
    AsconHash256,
    /// BLAKE2b with the requested output length in bits.
    Blake2b(u32),
    /// BLAKE2s with the requested output length in bits.
    Blake2s(u32),
    /// CRC-24 checksum.
    Crc24,
    /// MD5.
    Md5,
    /// RIPEMD-160.
    Ripemd160,
    /// SHA-1.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-512/256.
    Sha512_256,
    /// SHA-3 with the requested output length in bits.
    Sha3(u32),
    /// SHAKE-128 used as a fixed-output hash with the requested output length in bits.
    Shake128(u32),
    /// SHAKE-256 used as a fixed-output hash with the requested output length in bits.
    Shake256(u32),
    /// Skein-512 with the requested output length in bits.
    Skein512(u32),
    /// SM3.
    Sm3,
    /// Whirlpool.
    Whirlpool,
}

impl HashAlgorithm {
    /// Return the Botan interface string for this hash function.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::AsconHash256 => "Ascon-Hash256".to_string(),
            Self::Blake2b(output_bits) => format!("BLAKE2b({output_bits})"),
            Self::Blake2s(output_bits) => format!("BLAKE2s({output_bits})"),
            Self::Crc24 => "CRC24".to_string(),
            Self::Md5 => "MD5".to_string(),
            Self::Ripemd160 => "RIPEMD-160".to_string(),
            Self::Sha1 => "SHA-1".to_string(),
            Self::Sha224 => "SHA-224".to_string(),
            Self::Sha256 => "SHA-256".to_string(),
            Self::Sha384 => "SHA-384".to_string(),
            Self::Sha512 => "SHA-512".to_string(),
            Self::Sha512_256 => "SHA-512-256".to_string(),
            Self::Sha3(output_bits) => format!("SHA-3({output_bits})"),
            Self::Shake128(output_bits) => format!("SHAKE-128({output_bits})"),
            Self::Shake256(output_bits) => format!("SHAKE-256({output_bits})"),
            Self::Skein512(output_bits) => format!("Skein-512({output_bits})"),
            Self::Sm3 => "SM3".to_string(),
            Self::Whirlpool => "Whirlpool".to_string(),
        }
    }
}

impl HashAlgorithmIdentifier for HashAlgorithm {
    fn botan_name(&self) -> String {
        HashAlgorithm::botan_name(self)
    }
}

/// Block ciphers accepted by Botan's block cipher interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockCipherAlgorithm {
    /// Any Botan block cipher identifier not modeled by this enum, for example
    /// `Lion(SHA-256,ChaCha20,128)` or `Cascade(Serpent,Twofish)`.
    Arbitrary(String),
    /// AES-128.
    Aes128,
    /// AES-192.
    Aes192,
    /// AES-256.
    Aes256,
    /// ARIA-128.
    Aria128,
    /// ARIA-192.
    Aria192,
    /// ARIA-256.
    Aria256,
    /// Blowfish.
    Blowfish,
    /// Camellia-128.
    Camellia128,
    /// Camellia-192.
    Camellia192,
    /// Camellia-256.
    Camellia256,
    /// CAST-128.
    Cast128,
    /// DES.
    Des,
    /// IDEA.
    Idea,
    /// Kuznyechik.
    Kuznyechik,
    /// SEED.
    Seed,
    /// Serpent.
    Serpent,
    /// SHACAL2.
    Shacal2,
    /// SM4.
    Sm4,
    /// Threefish-512.
    Threefish512,
    /// TripleDES.
    TripleDes,
    /// Twofish.
    Twofish,
}

impl BlockCipherAlgorithm {
    /// Return the Botan interface string for this block cipher.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::Aes128 => "AES-128".to_string(),
            Self::Aes192 => "AES-192".to_string(),
            Self::Aes256 => "AES-256".to_string(),
            Self::Aria128 => "ARIA-128".to_string(),
            Self::Aria192 => "ARIA-192".to_string(),
            Self::Aria256 => "ARIA-256".to_string(),
            Self::Blowfish => "Blowfish".to_string(),
            Self::Camellia128 => "Camellia-128".to_string(),
            Self::Camellia192 => "Camellia-192".to_string(),
            Self::Camellia256 => "Camellia-256".to_string(),
            Self::Cast128 => "CAST-128".to_string(),
            Self::Des => "DES".to_string(),
            Self::Idea => "IDEA".to_string(),
            Self::Kuznyechik => "Kuznyechik".to_string(),
            Self::Seed => "SEED".to_string(),
            Self::Serpent => "Serpent".to_string(),
            Self::Shacal2 => "SHACAL2".to_string(),
            Self::Sm4 => "SM4".to_string(),
            Self::Threefish512 => "Threefish-512".to_string(),
            Self::TripleDes => "TripleDES".to_string(),
            Self::Twofish => "Twofish".to_string(),
        }
    }
}

impl BlockCipherAlgorithmIdentifier for BlockCipherAlgorithm {
    fn botan_name(&self) -> String {
        BlockCipherAlgorithm::botan_name(self)
    }
}

/// Padding schemes used by Botan block cipher modes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CipherPadding {
    /// Any Botan cipher padding identifier not modeled by this enum.
    Arbitrary(String),
    /// ANSI X9.23 padding.
    AnsiX923,
    /// Ciphertext stealing.
    Cts,
    /// ESP padding.
    Esp,
    /// No padding.
    NoPadding,
    /// One-and-zeros padding.
    OneAndZeros,
    /// PKCS#7 padding.
    Pkcs7,
}

impl CipherPadding {
    /// Return the Botan interface string for this padding scheme.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::AnsiX923 => "X9.23".to_string(),
            Self::Cts => "CTS".to_string(),
            Self::Esp => "ESP".to_string(),
            Self::NoPadding => "NoPadding".to_string(),
            Self::OneAndZeros => "OneAndZeros".to_string(),
            Self::Pkcs7 => "PKCS7".to_string(),
        }
    }
}

/// Stream ciphers accepted by Botan's cipher interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamCipherAlgorithm {
    /// Any Botan stream cipher identifier not modeled by this enum, for example
    /// a provider-specific stream cipher name.
    Arbitrary(String),
    /// ChaCha with 8 rounds.
    ChaCha8,
    /// ChaCha with 12 rounds.
    ChaCha12,
    /// ChaCha20.
    ChaCha20,
    /// CTR-BE mode over a block cipher, with an optional counter width in bytes.
    ///
    /// The counter width must be between 4 and the cipher's block size (the default).
    CtrBe(BlockCipherAlgorithm, Option<u32>),
    /// OFB mode over a block cipher, used as a stream cipher.
    Ofb(BlockCipherAlgorithm),
    /// RC4, with an optional number of initial keystream bytes to discard.
    Rc4(Option<u32>),
    /// Salsa20.
    Salsa20,
}

impl StreamCipherAlgorithm {
    /// Return the Botan interface string for this stream cipher.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::ChaCha8 => "ChaCha(8)".to_string(),
            Self::ChaCha12 => "ChaCha(12)".to_string(),
            Self::ChaCha20 => "ChaCha20".to_string(),
            Self::CtrBe(cipher, width) => ctr_be_name(cipher, *width),
            Self::Ofb(cipher) => format!("OFB({})", cipher.botan_name()),
            Self::Rc4(skip) => match skip {
                Some(skip) => format!("RC4({skip})"),
                None => "RC4".to_string(),
            },
            Self::Salsa20 => "Salsa20".to_string(),
        }
    }
}

impl CipherAlgorithmIdentifier for StreamCipherAlgorithm {
    fn botan_name(&self) -> String {
        StreamCipherAlgorithm::botan_name(self)
    }
}

/// Ciphers and cipher modes accepted by Botan's cipher interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CipherAlgorithm {
    /// Any Botan cipher identifier not modeled by this enum, for example
    /// a composed mode or provider-specific name.
    Arbitrary(String),
    /// Ascon-AEAD128 (NIST SP 800-232).
    AsconAead128,
    /// CBC mode with an optional padding scheme (PKCS#7 if unspecified).
    ///
    /// Note that uses which require naming a specific cipher mode, such as
    /// `Privkey::der_encode_encrypted_with_options`, accept only the
    /// unparameterized form.
    Cbc(BlockCipherAlgorithm, Option<CipherPadding>),
    /// CCM mode with an optional authentication tag length in bytes and an
    /// optional length field size (L) in bytes.
    ///
    /// If only the length field size is specified, the default tag length of
    /// 16 bytes is used.
    Ccm(BlockCipherAlgorithm, Option<u32>, Option<u32>),
    /// CFB mode with an optional feedback size in bits.
    Cfb(BlockCipherAlgorithm, Option<u32>),
    /// ChaCha20Poly1305 AEAD.
    ChaCha20Poly1305,
    /// CTR-BE mode, with an optional counter width in bytes.
    ///
    /// The counter width must be between 4 and the cipher's block size (the default).
    CtrBe(BlockCipherAlgorithm, Option<u32>),
    /// EAX mode with an optional authentication tag length in bytes.
    Eax(BlockCipherAlgorithm, Option<u32>),
    /// GCM mode with an optional authentication tag length in bytes.
    Gcm(BlockCipherAlgorithm, Option<u32>),
    /// GCM-SIV mode (RFC 8452).
    GcmSiv(BlockCipherAlgorithm),
    /// OCB mode with an optional authentication tag length in bytes.
    Ocb(BlockCipherAlgorithm, Option<u32>),
    /// SIV mode.
    Siv(BlockCipherAlgorithm),
    /// A stream cipher identifier.
    Stream(StreamCipherAlgorithm),
    /// XTS mode.
    Xts(BlockCipherAlgorithm),
}

impl CipherAlgorithm {
    /// Return the Botan interface string for this cipher or cipher mode.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::AsconAead128 => "Ascon-AEAD128".to_string(),
            Self::Cbc(cipher, padding) => match padding {
                Some(padding) => format!("{}/CBC/{}", cipher.botan_name(), padding.botan_name()),
                None => format!("{}/CBC", cipher.botan_name()),
            },
            Self::Ccm(cipher, tag_len, length_field) => match (tag_len, length_field) {
                (tag_len, Some(length_field)) => format!(
                    "{}/CCM({},{length_field})",
                    cipher.botan_name(),
                    tag_len.unwrap_or(16)
                ),
                (Some(tag_len), None) => format!("{}/CCM({tag_len})", cipher.botan_name()),
                (None, None) => format!("{}/CCM", cipher.botan_name()),
            },
            Self::Cfb(cipher, feedback_bits) => {
                mode_with_optional_u32(cipher, "CFB", *feedback_bits)
            }
            Self::ChaCha20Poly1305 => "ChaCha20Poly1305".to_string(),
            Self::CtrBe(cipher, width) => ctr_be_name(cipher, *width),
            Self::Eax(cipher, tag_len) => mode_with_optional_u32(cipher, "EAX", *tag_len),
            Self::Gcm(cipher, tag_len) => mode_with_optional_u32(cipher, "GCM", *tag_len),
            Self::GcmSiv(cipher) => format!("{}/GCM-SIV", cipher.botan_name()),
            Self::Ocb(cipher, tag_len) => mode_with_optional_u32(cipher, "OCB", *tag_len),
            Self::Siv(cipher) => format!("{}/SIV", cipher.botan_name()),
            Self::Stream(cipher) => cipher.botan_name(),
            Self::Xts(cipher) => format!("{}/XTS", cipher.botan_name()),
        }
    }
}

impl CipherAlgorithmIdentifier for CipherAlgorithm {
    fn botan_name(&self) -> String {
        CipherAlgorithm::botan_name(self)
    }
}

fn mode_with_optional_u32(
    cipher: &BlockCipherAlgorithm,
    mode: &str,
    parameter: Option<u32>,
) -> String {
    match parameter {
        Some(parameter) => format!("{}/{mode}({parameter})", cipher.botan_name()),
        None => format!("{}/{mode}", cipher.botan_name()),
    }
}

fn ctr_be_name(cipher: &BlockCipherAlgorithm, width: Option<u32>) -> String {
    match width {
        Some(width) => format!("CTR-BE({},{width})", cipher.botan_name()),
        None => format!("CTR-BE({})", cipher.botan_name()),
    }
}

/// Message authentication codes accepted by Botan's MAC interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacAlgorithm {
    /// Any Botan MAC identifier not modeled by this enum
    Arbitrary(String),
    /// BLAKE2b keyed MAC with the requested output length in bits.
    Blake2b(u32),
    /// CMAC over a block cipher.
    Cmac(BlockCipherAlgorithm),
    /// GMAC over a block cipher.
    Gmac(BlockCipherAlgorithm),
    /// HMAC over a hash function.
    Hmac(HashAlgorithm),
    /// KMAC-128 with the requested output length in bits.
    Kmac128(u32),
    /// KMAC-256 with the requested output length in bits.
    Kmac256(u32),
    /// Poly1305.
    Poly1305,
}

impl MacAlgorithm {
    /// Return the Botan interface string for this MAC.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::Blake2b(output_bits) => format!("BLAKE2b({output_bits})"),
            Self::Cmac(cipher) => format!("CMAC({})", cipher.botan_name()),
            Self::Gmac(cipher) => format!("GMAC({})", cipher.botan_name()),
            Self::Hmac(hash) => format!("HMAC({})", hash.botan_name()),
            Self::Kmac128(output_bits) => format!("KMAC-128({output_bits})"),
            Self::Kmac256(output_bits) => format!("KMAC-256({output_bits})"),
            Self::Poly1305 => "Poly1305".to_string(),
        }
    }
}

impl MacAlgorithmIdentifier for MacAlgorithm {
    fn botan_name(&self) -> String {
        MacAlgorithm::botan_name(self)
    }
}

/// Key derivation functions accepted by Botan's KDF interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KdfAlgorithm {
    /// Any Botan KDF identifier not modeled by this enum
    Arbitrary(String),
    /// HKDF using HMAC with a hash function.
    Hkdf(HashAlgorithm),
    /// HKDF-Expand using HMAC with a hash function.
    HkdfExpand(HashAlgorithm),
    /// HKDF-Expand using an arbitrary MAC.
    HkdfExpandMac(MacAlgorithm),
    /// HKDF-Extract using HMAC with a hash function.
    HkdfExtract(HashAlgorithm),
    /// HKDF-Extract using an arbitrary MAC.
    HkdfExtractMac(MacAlgorithm),
    /// HKDF using an arbitrary MAC.
    HkdfMac(MacAlgorithm),
    /// KDF1 using a hash function.
    Kdf1(HashAlgorithm),
    /// KDF1 from ISO 18033 using a hash function.
    Kdf1Iso18033(HashAlgorithm),
    /// KDF2 using a hash function.
    Kdf2(HashAlgorithm),
    /// Return the raw shared secret.
    Raw,
    /// SP800-56A using a hash function.
    Sp80056aHash(HashAlgorithm),
    /// SP800-56A using a MAC.
    Sp80056aMac(MacAlgorithm),
    /// SP800-56C using HMAC with a hash function.
    Sp80056cHash(HashAlgorithm),
    /// SP800-56C using a MAC.
    Sp80056cMac(MacAlgorithm),
    /// SP800-108 counter mode using a MAC, with optional counter and output
    /// length field sizes in bits (each defaulting to 32).
    ///
    /// If only the output length field size is specified, the default
    /// counter size of 32 bits is emitted explicitly.
    Sp800108Counter(MacAlgorithm, Option<u32>, Option<u32>),
    /// SP800-108 feedback mode using a MAC, with optional counter and output
    /// length field sizes in bits (each defaulting to 32).
    ///
    /// If only the output length field size is specified, the default
    /// counter size of 32 bits is emitted explicitly.
    Sp800108Feedback(MacAlgorithm, Option<u32>, Option<u32>),
    /// SP800-108 pipeline mode using a MAC, with optional counter and output
    /// length field sizes in bits (each defaulting to 32).
    ///
    /// If only the output length field size is specified, the default
    /// counter size of 32 bits is emitted explicitly.
    Sp800108Pipeline(MacAlgorithm, Option<u32>, Option<u32>),
    /// TLS 1.2 PRF using HMAC with a hash function.
    Tls12Prf(HashAlgorithm),
    /// TLS 1.2 PRF using an arbitrary MAC.
    Tls12PrfMac(MacAlgorithm),
    /// ANSI X9.42 PRF with an algorithm object identifier or symbolic name.
    X942Prf(String),
}

impl KdfAlgorithm {
    /// Return the Botan interface string for this KDF.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::Hkdf(hash) => format!("HKDF({})", hash.botan_name()),
            Self::HkdfExpand(hash) => format!("HKDF-Expand({})", hash.botan_name()),
            Self::HkdfExpandMac(mac) => format!("HKDF-Expand({})", mac.botan_name()),
            Self::HkdfExtract(hash) => format!("HKDF-Extract({})", hash.botan_name()),
            Self::HkdfExtractMac(mac) => format!("HKDF-Extract({})", mac.botan_name()),
            Self::HkdfMac(mac) => format!("HKDF({})", mac.botan_name()),
            Self::Kdf1(hash) => format!("KDF1({})", hash.botan_name()),
            Self::Kdf1Iso18033(hash) => format!("KDF1-18033({})", hash.botan_name()),
            Self::Kdf2(hash) => format!("KDF2({})", hash.botan_name()),
            Self::Raw => "Raw".to_string(),
            Self::Sp80056aHash(hash) => format!("SP800-56A({})", hash.botan_name()),
            Self::Sp80056aMac(mac) => format!("SP800-56A({})", mac.botan_name()),
            Self::Sp80056cHash(hash) => format!("SP800-56C({})", hash.botan_name()),
            Self::Sp80056cMac(mac) => format!("SP800-56C({})", mac.botan_name()),
            Self::Sp800108Counter(mac, counter_bits, length_bits) => {
                sp800_108_name("SP800-108-Counter", mac, *counter_bits, *length_bits)
            }
            Self::Sp800108Feedback(mac, counter_bits, length_bits) => {
                sp800_108_name("SP800-108-Feedback", mac, *counter_bits, *length_bits)
            }
            Self::Sp800108Pipeline(mac, counter_bits, length_bits) => {
                sp800_108_name("SP800-108-Pipeline", mac, *counter_bits, *length_bits)
            }
            Self::Tls12Prf(hash) => format!("TLS-12-PRF({})", hash.botan_name()),
            Self::Tls12PrfMac(mac) => format!("TLS-12-PRF({})", mac.botan_name()),
            Self::X942Prf(key_wrap_oid) => format!("X9.42-PRF({key_wrap_oid})"),
        }
    }
}

impl KdfAlgorithmIdentifier for KdfAlgorithm {
    fn botan_name(&self) -> String {
        KdfAlgorithm::botan_name(self)
    }
}

fn sp800_108_name(
    name: &str,
    mac: &MacAlgorithm,
    counter_bits: Option<u32>,
    length_bits: Option<u32>,
) -> String {
    match (counter_bits, length_bits) {
        (counter_bits, Some(length_bits)) => {
            format!(
                "{}({},{},{length_bits})",
                name,
                mac.botan_name(),
                counter_bits.unwrap_or(32)
            )
        }
        (Some(counter_bits), None) => format!("{}({},{counter_bits})", name, mac.botan_name()),
        (None, None) => format!("{}({})", name, mac.botan_name()),
    }
}

/// Password hashing and password based KDF algorithms accepted by Botan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordHashAlgorithm {
    /// Any Botan password hash identifier not modeled by this enum, for example
    /// a password hash added by a newer Botan release.
    Arbitrary(String),
    /// Argon2d.
    Argon2d,
    /// Argon2i.
    Argon2i,
    /// Argon2id.
    Argon2id,
    /// bcrypt-PBKDF.
    BcryptPbkdf,
    /// OpenPGP S2K using a hash function.
    OpenPgpS2k(HashAlgorithm),
    /// PBKDF2 using HMAC with a hash function.
    Pbkdf2(HashAlgorithm),
    /// PBKDF2 using an arbitrary MAC as the PRF.
    Pbkdf2Mac(MacAlgorithm),
    /// PKCS #12 KDF using a hash function, with the purpose ID byte
    /// (1 = encryption key, 2 = IV, 3 = MAC key).
    Pkcs12Kdf(HashAlgorithm, u32),
    /// scrypt.
    Scrypt,
}

impl PasswordHashAlgorithm {
    /// Return the Botan interface string for this password hash or password based KDF.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::Argon2d => "Argon2d".to_string(),
            Self::Argon2i => "Argon2i".to_string(),
            Self::Argon2id => "Argon2id".to_string(),
            Self::BcryptPbkdf => "Bcrypt-PBKDF".to_string(),
            Self::OpenPgpS2k(hash) => format!("OpenPGP-S2K({})", hash.botan_name()),
            Self::Pbkdf2(hash) => format!("PBKDF2({})", hash.botan_name()),
            Self::Pbkdf2Mac(mac) => format!("PBKDF2({})", mac.botan_name()),
            Self::Pkcs12Kdf(hash, id) => format!("PKCS12-KDF({},{id})", hash.botan_name()),
            Self::Scrypt => "Scrypt".to_string(),
        }
    }
}

impl PasswordHashAlgorithmIdentifier for PasswordHashAlgorithm {
    fn botan_name(&self) -> String {
        PasswordHashAlgorithm::botan_name(self)
    }
}

/// KDFs accepted when exporting an encrypted PKCS #8 private key.
///
/// Note that this interface differs from the rest of the library: the
/// PBKDF2 case is named by its digest alone (for example `SHA-512`), with
/// a `PBKDF2(...)` expression not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pkcs8Kdf {
    /// Any Botan PKCS #8 KDF identifier not modeled by this enum.
    Arbitrary(String),
    /// PBKDF2 using HMAC with the given hash function.
    Pbkdf2(HashAlgorithm),
    /// scrypt.
    Scrypt,
}

impl Pkcs8Kdf {
    /// Return the Botan interface string for this PKCS #8 KDF.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::Pbkdf2(hash) => hash.botan_name(),
            Self::Scrypt => "Scrypt".to_string(),
        }
    }
}

impl Pkcs8KdfIdentifier for Pkcs8Kdf {
    fn botan_name(&self) -> String {
        Pkcs8Kdf::botan_name(self)
    }
}

/// Public key algorithms accepted by Botan's key creation interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    /// Any Botan public key algorithm identifier not modeled by this enum, for example
    /// certain obsolescent algorithms (like `DSA` and `ElGamal`), or deprecated
    /// post-quantum schemes under their pre-standardization names (like `Kyber`
    /// and `Dilithium`).
    Arbitrary(String),
    /// Classic McEliece.
    ClassicMcEliece,
    /// Finite Field Diffie-Hellman.
    Dh,
    /// ECDH.
    Ecdh,
    /// ECDSA.
    Ecdsa,
    /// ECGDSA.
    Ecgdsa,
    /// ECKCDSA.
    Eckcdsa,
    /// Ed25519.
    Ed25519,
    /// Ed448.
    Ed448,
    /// FrodoKEM.
    FrodoKem,
    /// HSS-LMS.
    HssLms,
    /// ML-DSA (FIPS 204, formerly Dilithium).
    MlDsa,
    /// ML-KEM (FIPS 203, formerly Kyber).
    MlKem,
    /// RSA.
    Rsa,
    /// SLH-DSA (FIPS 205, formerly SPHINCS+).
    SlhDsa,
    /// SM2.
    Sm2,
    /// X25519.
    X25519,
    /// X448.
    X448,
    /// XMSS.
    Xmss,
}

impl PublicKeyAlgorithm {
    /// Return the Botan interface string for this public key algorithm.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::ClassicMcEliece => "ClassicMcEliece".to_string(),
            Self::Dh => "DH".to_string(),
            Self::Ecdh => "ECDH".to_string(),
            Self::Ecdsa => "ECDSA".to_string(),
            Self::Ecgdsa => "ECGDSA".to_string(),
            Self::Eckcdsa => "ECKCDSA".to_string(),
            Self::Ed25519 => "Ed25519".to_string(),
            Self::Ed448 => "Ed448".to_string(),
            Self::FrodoKem => "FrodoKEM".to_string(),
            Self::HssLms => "HSS-LMS".to_string(),
            Self::MlDsa => "ML-DSA".to_string(),
            Self::MlKem => "ML-KEM".to_string(),
            Self::Rsa => "RSA".to_string(),
            Self::SlhDsa => "SLH-DSA".to_string(),
            Self::Sm2 => "SM2".to_string(),
            Self::X25519 => "X25519".to_string(),
            Self::X448 => "X448".to_string(),
            Self::Xmss => "XMSS".to_string(),
        }
    }
}

impl PublicKeyAlgorithmIdentifier for PublicKeyAlgorithm {
    fn botan_name(&self) -> String {
        PublicKeyAlgorithm::botan_name(self)
    }
}

/// The bit length of the modulus, when creating an RSA key.
impl KeyGenParamsIdentifier for u32 {
    fn botan_name(&self) -> String {
        self.to_string()
    }
}

macro_rules! define_keygen_params_enum {
    ($(#[$meta:meta])* $name:ident, $($(#[$vmeta:meta])* $variant:ident => $botan_name:literal),+ $(,)?) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum $name {
            $($(#[$vmeta])* $variant),+
        }

        impl $name {
            /// Return the Botan interface string for this parameter set.
            #[must_use]
            pub fn botan_name(&self) -> String {
                match self {
                    $(Self::$variant => $botan_name.to_string()),+
                }
            }
        }

        impl KeyGenParamsIdentifier for $name {
            fn botan_name(&self) -> String {
                $name::botan_name(self)
            }
        }
    };
}

/// Elliptic curve groups accepted for key creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcGroupId {
    /// Any Botan EC group identifier not modeled by this enum, for example
    /// an application specific group or a deprecated curve such as `x962_p239v1`.
    Arbitrary(String),
    /// brainpool256r1.
    Brainpool256r1,
    /// brainpool384r1.
    Brainpool384r1,
    /// brainpool512r1.
    Brainpool512r1,
    /// frp256v1.
    Frp256v1,
    /// numsp512d1.
    Numsp512d1,
    /// secp192r1, also known as P-192.
    Secp192r1,
    /// secp224r1, also known as P-224.
    Secp224r1,
    /// secp256k1.
    Secp256k1,
    /// secp256r1, also known as P-256.
    Secp256r1,
    /// secp384r1, also known as P-384.
    Secp384r1,
    /// secp521r1, also known as P-521.
    Secp521r1,
    /// sm2p256v1.
    Sm2p256v1,
}

impl EcGroupId {
    /// Return the Botan interface string for this EC group.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::Brainpool256r1 => "brainpool256r1".to_string(),
            Self::Brainpool384r1 => "brainpool384r1".to_string(),
            Self::Brainpool512r1 => "brainpool512r1".to_string(),
            Self::Frp256v1 => "frp256v1".to_string(),
            Self::Numsp512d1 => "numsp512d1".to_string(),
            Self::Secp192r1 => "secp192r1".to_string(),
            Self::Secp224r1 => "secp224r1".to_string(),
            Self::Secp256k1 => "secp256k1".to_string(),
            Self::Secp256r1 => "secp256r1".to_string(),
            Self::Secp384r1 => "secp384r1".to_string(),
            Self::Secp521r1 => "secp521r1".to_string(),
            Self::Sm2p256v1 => "sm2p256v1".to_string(),
        }
    }
}

impl KeyGenParamsIdentifier for EcGroupId {
    fn botan_name(&self) -> String {
        EcGroupId::botan_name(self)
    }
}

/// Discrete logarithm groups accepted for Diffie-Hellman key creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DlGroup {
    /// Any Botan DL group identifier not modeled by this enum, for example
    /// a deprecated group such as `modp/ietf/1024`.
    Arbitrary(String),
    /// RFC 7919 ffdhe/ietf/2048.
    FfdheIetf2048,
    /// RFC 7919 ffdhe/ietf/3072.
    FfdheIetf3072,
    /// RFC 7919 ffdhe/ietf/4096.
    FfdheIetf4096,
    /// RFC 7919 ffdhe/ietf/6144.
    FfdheIetf6144,
    /// RFC 7919 ffdhe/ietf/8192.
    FfdheIetf8192,
    /// RFC 3526 modp/ietf/2048.
    ModpIetf2048,
    /// RFC 3526 modp/ietf/3072.
    ModpIetf3072,
    /// RFC 3526 modp/ietf/4096.
    ModpIetf4096,
    /// RFC 3526 modp/ietf/6144.
    ModpIetf6144,
    /// RFC 3526 modp/ietf/8192.
    ModpIetf8192,
}

impl DlGroup {
    /// Return the Botan interface string for this DL group.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::FfdheIetf2048 => "ffdhe/ietf/2048".to_string(),
            Self::FfdheIetf3072 => "ffdhe/ietf/3072".to_string(),
            Self::FfdheIetf4096 => "ffdhe/ietf/4096".to_string(),
            Self::FfdheIetf6144 => "ffdhe/ietf/6144".to_string(),
            Self::FfdheIetf8192 => "ffdhe/ietf/8192".to_string(),
            Self::ModpIetf2048 => "modp/ietf/2048".to_string(),
            Self::ModpIetf3072 => "modp/ietf/3072".to_string(),
            Self::ModpIetf4096 => "modp/ietf/4096".to_string(),
            Self::ModpIetf6144 => "modp/ietf/6144".to_string(),
            Self::ModpIetf8192 => "modp/ietf/8192".to_string(),
        }
    }
}

impl KeyGenParamsIdentifier for DlGroup {
    fn botan_name(&self) -> String {
        DlGroup::botan_name(self)
    }
}

define_keygen_params_enum!(
    /// ML-KEM parameter sets.
    MlKemParams,
    /// ML-KEM-512.
    MlKem512 => "ML-KEM-512",
    /// ML-KEM-768.
    MlKem768 => "ML-KEM-768",
    /// ML-KEM-1024.
    MlKem1024 => "ML-KEM-1024",
);

define_keygen_params_enum!(
    /// ML-DSA parameter sets.
    MlDsaParams,
    /// ML-DSA-4x4.
    MlDsa4x4 => "ML-DSA-4x4",
    /// ML-DSA-6x5.
    MlDsa6x5 => "ML-DSA-6x5",
    /// ML-DSA-8x7.
    MlDsa8x7 => "ML-DSA-8x7",
);

define_keygen_params_enum!(
    /// SLH-DSA parameter sets.
    SlhDsaParams,
    /// SLH-DSA-SHA2-128s.
    Sha2_128s => "SLH-DSA-SHA2-128s",
    /// SLH-DSA-SHA2-128f.
    Sha2_128f => "SLH-DSA-SHA2-128f",
    /// SLH-DSA-SHA2-192s.
    Sha2_192s => "SLH-DSA-SHA2-192s",
    /// SLH-DSA-SHA2-192f.
    Sha2_192f => "SLH-DSA-SHA2-192f",
    /// SLH-DSA-SHA2-256s.
    Sha2_256s => "SLH-DSA-SHA2-256s",
    /// SLH-DSA-SHA2-256f.
    Sha2_256f => "SLH-DSA-SHA2-256f",
    /// SLH-DSA-SHAKE-128s.
    Shake128s => "SLH-DSA-SHAKE-128s",
    /// SLH-DSA-SHAKE-128f.
    Shake128f => "SLH-DSA-SHAKE-128f",
    /// SLH-DSA-SHAKE-192s.
    Shake192s => "SLH-DSA-SHAKE-192s",
    /// SLH-DSA-SHAKE-192f.
    Shake192f => "SLH-DSA-SHAKE-192f",
    /// SLH-DSA-SHAKE-256s.
    Shake256s => "SLH-DSA-SHAKE-256s",
    /// SLH-DSA-SHAKE-256f.
    Shake256f => "SLH-DSA-SHAKE-256f",
);

define_keygen_params_enum!(
    /// FrodoKEM parameter sets.
    FrodoKemParams,
    /// FrodoKEM-640-SHAKE.
    Frodo640Shake => "FrodoKEM-640-SHAKE",
    /// FrodoKEM-976-SHAKE.
    Frodo976Shake => "FrodoKEM-976-SHAKE",
    /// FrodoKEM-1344-SHAKE.
    Frodo1344Shake => "FrodoKEM-1344-SHAKE",
    /// FrodoKEM-640-AES.
    Frodo640Aes => "FrodoKEM-640-AES",
    /// FrodoKEM-976-AES.
    Frodo976Aes => "FrodoKEM-976-AES",
    /// FrodoKEM-1344-AES.
    Frodo1344Aes => "FrodoKEM-1344-AES",
    /// eFrodoKEM-640-SHAKE.
    EFrodo640Shake => "eFrodoKEM-640-SHAKE",
    /// eFrodoKEM-976-SHAKE.
    EFrodo976Shake => "eFrodoKEM-976-SHAKE",
    /// eFrodoKEM-1344-SHAKE.
    EFrodo1344Shake => "eFrodoKEM-1344-SHAKE",
    /// eFrodoKEM-640-AES.
    EFrodo640Aes => "eFrodoKEM-640-AES",
    /// eFrodoKEM-976-AES.
    EFrodo976Aes => "eFrodoKEM-976-AES",
    /// eFrodoKEM-1344-AES.
    EFrodo1344Aes => "eFrodoKEM-1344-AES",
);

define_keygen_params_enum!(
    /// Classic McEliece parameter sets.
    ClassicMcElieceParams,
    /// ClassicMcEliece_348864.
    P348864 => "ClassicMcEliece_348864",
    /// ClassicMcEliece_348864f.
    P348864f => "ClassicMcEliece_348864f",
    /// ClassicMcEliece_460896.
    P460896 => "ClassicMcEliece_460896",
    /// ClassicMcEliece_460896f.
    P460896f => "ClassicMcEliece_460896f",
    /// ClassicMcEliece_6688128.
    P6688128 => "ClassicMcEliece_6688128",
    /// ClassicMcEliece_6688128f.
    P6688128f => "ClassicMcEliece_6688128f",
    /// ClassicMcEliece_6688128pc.
    P6688128pc => "ClassicMcEliece_6688128pc",
    /// ClassicMcEliece_6688128pcf.
    P6688128pcf => "ClassicMcEliece_6688128pcf",
    /// ClassicMcEliece_6960119.
    P6960119 => "ClassicMcEliece_6960119",
    /// ClassicMcEliece_6960119f.
    P6960119f => "ClassicMcEliece_6960119f",
    /// ClassicMcEliece_6960119pc.
    P6960119pc => "ClassicMcEliece_6960119pc",
    /// ClassicMcEliece_6960119pcf.
    P6960119pcf => "ClassicMcEliece_6960119pcf",
    /// ClassicMcEliece_8192128.
    P8192128 => "ClassicMcEliece_8192128",
    /// ClassicMcEliece_8192128f.
    P8192128f => "ClassicMcEliece_8192128f",
    /// ClassicMcEliece_8192128pc.
    P8192128pc => "ClassicMcEliece_8192128pc",
    /// ClassicMcEliece_8192128pcf.
    P8192128pcf => "ClassicMcEliece_8192128pcf",
);

define_keygen_params_enum!(
    /// XMSS parameter sets.
    XmssParams,
    /// XMSS-SHA2_10_256.
    Sha2_10_256 => "XMSS-SHA2_10_256",
    /// XMSS-SHA2_16_256.
    Sha2_16_256 => "XMSS-SHA2_16_256",
    /// XMSS-SHA2_20_256.
    Sha2_20_256 => "XMSS-SHA2_20_256",
    /// XMSS-SHA2_10_512.
    Sha2_10_512 => "XMSS-SHA2_10_512",
    /// XMSS-SHA2_16_512.
    Sha2_16_512 => "XMSS-SHA2_16_512",
    /// XMSS-SHA2_20_512.
    Sha2_20_512 => "XMSS-SHA2_20_512",
    /// XMSS-SHA2_10_192.
    Sha2_10_192 => "XMSS-SHA2_10_192",
    /// XMSS-SHA2_16_192.
    Sha2_16_192 => "XMSS-SHA2_16_192",
    /// XMSS-SHA2_20_192.
    Sha2_20_192 => "XMSS-SHA2_20_192",
    /// XMSS-SHAKE_10_256.
    Shake10_256 => "XMSS-SHAKE_10_256",
    /// XMSS-SHAKE_16_256.
    Shake16_256 => "XMSS-SHAKE_16_256",
    /// XMSS-SHAKE_20_256.
    Shake20_256 => "XMSS-SHAKE_20_256",
    /// XMSS-SHAKE_10_512.
    Shake10_512 => "XMSS-SHAKE_10_512",
    /// XMSS-SHAKE_16_512.
    Shake16_512 => "XMSS-SHAKE_16_512",
    /// XMSS-SHAKE_20_512.
    Shake20_512 => "XMSS-SHAKE_20_512",
    /// XMSS-SHAKE256_10_256.
    Shake256_10_256 => "XMSS-SHAKE256_10_256",
    /// XMSS-SHAKE256_16_256.
    Shake256_16_256 => "XMSS-SHAKE256_16_256",
    /// XMSS-SHAKE256_20_256.
    Shake256_20_256 => "XMSS-SHAKE256_20_256",
    /// XMSS-SHAKE256_10_192.
    Shake256_10_192 => "XMSS-SHAKE256_10_192",
    /// XMSS-SHAKE256_16_192.
    Shake256_16_192 => "XMSS-SHAKE256_16_192",
    /// XMSS-SHAKE256_20_192.
    Shake256_20_192 => "XMSS-SHAKE256_20_192",
);

/// Parameters controlling public key encryption and decryption.
///
/// Each encryption scheme accepts a specific subset of these parameters;
/// passing parameters a scheme does not support causes an error when the
/// operation is created, rather than the parameters being ignored.
///
/// For SM2, `None` (where an `Option<EncryptionParams>` is accepted)
/// selects the default hash SM3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptionParams {
    /// Any Botan public key encryption parameter string not modeled by this enum.
    Arbitrary(String),
    /// Raw public key operation without padding.
    Raw,
    /// RSA OAEP encryption padding.
    RsaOaep {
        /// The hash function used for OAEP, and for MGF1 unless a separate
        /// MGF1 hash is specified.
        hash: HashAlgorithm,
        /// A separate hash function used for MGF1.
        mgf1_hash: Option<HashAlgorithm>,
        /// The OAEP label; empty if not specified.
        ///
        /// Note that a label containing characters significant to Botan's
        /// algorithm grammar (such as commas or parentheses) cannot be
        /// expressed.
        label: Option<String>,
    },
    /// RSA PKCS#1 v1.5 encryption padding.
    RsaPkcs1v15,
    /// SM2 encryption using the named hash function.
    Sm2(HashAlgorithm),
}

impl EncryptionParams {
    /// Return the Botan interface string for these encryption parameters.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::Raw => "Raw".to_string(),
            Self::RsaOaep {
                hash,
                mgf1_hash,
                label,
            } => {
                let mgf1 = match mgf1_hash {
                    Some(mgf1_hash) => format!("MGF1({})", mgf1_hash.botan_name()),
                    None => "MGF1".to_string(),
                };
                match label {
                    Some(label) => format!("OAEP({},{mgf1},{label})", hash.botan_name()),
                    None => format!("OAEP({},{mgf1})", hash.botan_name()),
                }
            }
            Self::RsaPkcs1v15 => "PKCS1v15".to_string(),
            Self::Sm2(hash) => hash.botan_name(),
        }
    }
}

impl EncryptionParamsIdentifier for EncryptionParams {
    fn botan_name(&self) -> String {
        EncryptionParams::botan_name(self)
    }
}

impl EncryptionParamsIdentifier for Option<EncryptionParams> {
    fn botan_name(&self) -> String {
        match self {
            Some(params) => EncryptionParams::botan_name(params),
            None => String::new(),
        }
    }
}

/// Parameters controlling public key signature generation and verification.
///
/// Each signature scheme accepts a specific subset of these parameters;
/// passing parameters a scheme does not support causes an error when the
/// operation is created, rather than the parameters being ignored.
///
/// For schemes that require no parameters (Ed25519 and Ed448 in their pure
/// modes, ML-DSA and SLH-DSA in their default hedged randomized modes,
/// HSS-LMS, and XMSS), pass `None` where an `Option<SignatureParams>` is
/// accepted; this translates to the empty parameter string.
///
/// A `HashAlgorithm` is also accepted directly anywhere `SignatureParams`
/// are, equivalent to `SignatureParams::Hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureParams {
    /// Any Botan signature parameter string not modeled by this enum, for
    /// example the deprecated `ISO_9796_DS2` RSA padding or a nonstandard
    /// Ed25519 prehash function.
    Arbitrary(String),
    /// Deterministic signing for ML-DSA or SLH-DSA, in place of the default
    /// hedged randomized signing.
    Deterministic,
    /// Ed25519 prehash mode (RFC 8032 Ed25519ph).
    Ed25519ph,
    /// Ed448 prehash mode (RFC 8032 Ed448ph).
    Ed448ph,
    /// Sign under the named hash function, for ECDSA, ECGDSA, ECKCDSA, and
    /// other hash parameterized signature schemes.
    Hash(HashAlgorithm),
    /// Explicitly request the default hedged randomized signing for ML-DSA
    /// or SLH-DSA.
    Randomized,
    /// Sign the input directly without hashing. The optional hash declares
    /// which digest the input is, allowing its length to be checked.
    Raw(Option<HashAlgorithm>),
    /// RSA PKCS#1 v1.5 signature padding using a hash function.
    RsaPkcs1v15(HashAlgorithm),
    /// RSA PKCS#1 v1.5 signature padding over an input that was already
    /// hashed. The optional hash causes the respective digest identifier to
    /// be included in the padding.
    RsaPkcs1v15Raw(Option<HashAlgorithm>),
    /// RSA-PSS using a hash function, with an optional salt length in bytes
    /// (defaulting to the hash output length).
    RsaPss {
        /// The hash function used for the message and MGF1.
        hash: HashAlgorithm,
        /// The salt length in bytes; during verification, an explicit salt
        /// length is enforced rather than accepting any length.
        salt_len: Option<u32>,
    },
    /// RSA-PSS over an input that was already hashed.
    RsaPssRaw {
        /// The hash function the input was hashed with, also used for MGF1.
        hash: HashAlgorithm,
        /// The salt length in bytes; during verification, an explicit salt
        /// length is enforced rather than accepting any length.
        salt_len: Option<u32>,
    },
    /// RSA X9.31 signature padding using a hash function.
    RsaX931(HashAlgorithm),
    /// SM2 signing with the given user identifier and hash. If no hash is
    /// specified, SM3 is used.
    ///
    /// Note that a user identifier containing a comma cannot be expressed.
    Sm2 {
        /// The user identifier.
        user_id: String,
        /// The hash function to use; SM3 if not specified.
        hash: Option<HashAlgorithm>,
    },
}

impl SignatureParams {
    /// Return the Botan interface string for these signature parameters.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::Deterministic => "Deterministic".to_string(),
            Self::Ed25519ph => "Ed25519ph".to_string(),
            Self::Ed448ph => "Ed448ph".to_string(),
            Self::Hash(hash) => hash_sig_padding_name(hash),
            Self::Randomized => "Randomized".to_string(),
            Self::Raw(None) => "Raw".to_string(),
            Self::Raw(Some(hash)) => format!("Raw({})", hash.botan_name()),
            Self::RsaPkcs1v15(hash) => format!("PKCS1v15({})", hash.botan_name()),
            Self::RsaPkcs1v15Raw(None) => "PKCS1v15(Raw)".to_string(),
            Self::RsaPkcs1v15Raw(Some(hash)) => format!("PKCS1v15(Raw,{})", hash.botan_name()),
            Self::RsaPss { hash, salt_len } => pss_name("PSS", hash, *salt_len),
            Self::RsaPssRaw { hash, salt_len } => pss_name("PSS_Raw", hash, *salt_len),
            Self::RsaX931(hash) => format!("X9.31({})", hash.botan_name()),
            Self::Sm2 { user_id, hash } => match hash {
                Some(hash) => format!("{user_id},{}", hash.botan_name()),
                None => user_id.clone(),
            },
        }
    }
}

fn hash_sig_padding_name(hash: &HashAlgorithm) -> String {
    // Botan 2 accepts only the "EMSA1(hash)" spelling here.
    if crate::Version::major_version() == 2 {
        format!("EMSA1({})", hash.botan_name())
    } else {
        hash.botan_name()
    }
}

fn pss_name(scheme: &str, hash: &HashAlgorithm, salt_len: Option<u32>) -> String {
    match salt_len {
        Some(salt_len) => format!("{scheme}({},MGF1,{salt_len})", hash.botan_name()),
        None => format!("{scheme}({})", hash.botan_name()),
    }
}

impl SignatureParamsIdentifier for SignatureParams {
    fn botan_name(&self) -> String {
        SignatureParams::botan_name(self)
    }
}

impl SignatureParamsIdentifier for HashAlgorithm {
    fn botan_name(&self) -> String {
        hash_sig_padding_name(self)
    }
}

impl SignatureParamsIdentifier for Option<SignatureParams> {
    fn botan_name(&self) -> String {
        match self {
            Some(params) => SignatureParams::botan_name(params),
            None => String::new(),
        }
    }
}

/// Random number generator types accepted by Botan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RngType {
    /// Any Botan RNG type identifier not modeled by this enum, for example
    /// a provider-specific RNG name.
    Arbitrary(String),
    /// ESDM RNG, fully seeded.
    EsdmFull,
    /// ESDM RNG with prediction resistance.
    EsdmPr,
    /// Processor hardware RNG (e.g. RDRAND), when available.
    Hwrng,
    /// Jitter RNG.
    Jitter,
    /// System RNG.
    System,
    /// Userspace RNG.
    User,
}

impl RngType {
    /// Return the Botan interface string for this RNG type.
    #[must_use]
    pub fn botan_name(&self) -> String {
        match self {
            Self::Arbitrary(name) => name.clone(),
            Self::EsdmFull => "esdm-full".to_string(),
            Self::EsdmPr => "esdm-pr".to_string(),
            Self::Hwrng => "hwrng".to_string(),
            Self::Jitter => "jitter".to_string(),
            Self::System => "system".to_string(),
            Self::User => "user".to_string(),
        }
    }
}

impl RngTypeIdentifier for RngType {
    fn botan_name(&self) -> String {
        RngType::botan_name(self)
    }
}

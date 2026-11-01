use crate::EncryptedKeyError;
use rand::{thread_rng, RngCore};
use sha1::Sha1;
use std::{
    convert::TryFrom,
    fmt::{Display, Formatter},
    str::FromStr,
};

pub const SALT_LENGTH: usize = 8;
pub const HASH_LENGTH: usize = 20;
pub const DEFAULT_PREFIX: &str = "16";

const EXPBIAS: u8 = 6;

/// A representation of a Tor hashed pssword. See the [module docs](../lib) for more details and examples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKey {
    prefix: &'static str,
    salt: [u8; SALT_LENGTH],
    hash: [u8; HASH_LENGTH],
}

impl EncryptedKey {
    /// Generate a hashed password using the given secret password. The result is random because the algorithm uses
    /// an 8-byte random salt.
    pub fn hash_password(secret: &str) -> Self {
        let salt = Self::random_salt();
        Self::hash_with_salt(secret, salt)
    }

    /// Generate a hashed password using the given secret password *and the supplied salt*. The result is deterministic.
    pub fn hash_with_salt(secret: &str, salt: [u8; SALT_LENGTH]) -> Self {
        let hash = Self::hash_secret(&salt, secret);
        Self {
            prefix: DEFAULT_PREFIX,
            salt,
            hash,
        }
    }

    /// Checks to see if the given password matches this hashed password
    pub fn validate(&self, secret: &str) -> bool {
        let other = Self::hash_with_salt(secret, self.salt);
        constant_time_eq(&self.hash, &other.hash)
    }

    /// Returns the salt portion of the hashed password
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Returns the indicator (always 0x60 in current Tor version)
    pub fn indicator() -> u8 {
        0x60
    }

    /// Returns the hash portion of the hashed password
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// Returns the hashed password prefix (always "16" for now)
    pub fn prefix(&self) -> &str {
        self.prefix
    }

    // Implemented according to S2K algorithm in RFC 2440 (OpenPGP)
    fn hash_secret(salt: &[u8], secret: &str) -> [u8; 20] {
        let c = Self::indicator();
        // Could be replaced by a const if indicator doesn't ever change, but leaving the door open for future changes
        // there.
        let count = (16usize + (c & 15) as usize) << ((c >> 4) + EXPBIAS);

        let mut sha = Sha1::new();
        let input = [salt, secret.as_bytes()].concat();
        let secret_len = input.len();
        // Per RFC 2440 Section 3.6.1.3 / RFC 4880 Section 3.7.1.3:
        // if the count is less than the size of the salt plus passphrase,
        // the full salt plus passphrase must still be hashed.
        let mut remaining = count.max(secret_len);

        while remaining > 0 {
            if remaining > secret_len {
                sha.update(&input);
                remaining = remaining.saturating_sub(secret_len);
            } else {
                sha.update(&input[..remaining]);
                remaining = 0;
            }
        }
        sha.digest().bytes()
    }

    fn random_salt() -> [u8; SALT_LENGTH] {
        let mut salt = [0u8; SALT_LENGTH];
        thread_rng().fill_bytes(&mut salt);
        salt
    }

    /// Tries to create an `EncryptedKey` instance from the string-like reference.
    pub fn try_convert<S: AsRef<str>>(s: S) -> Result<Self, EncryptedKeyError> {
        if s.as_ref().len() != 61 {
            return Err(EncryptedKeyError::InvalidLength);
        }
        if !s.as_ref().starts_with("16:") {
            return Err(EncryptedKeyError::UnsupportedPrefix);
        }
        let mut bytes = [0u8; 29];
        hex::decode_to_slice(&s.as_ref().as_bytes()[3..], &mut bytes)?;

        // Indicator is always 0x60
        if bytes[8] != 0x60 {
            return Err(EncryptedKeyError::InvalidIndicator);
        }
        let mut salt = [0u8; SALT_LENGTH];
        salt.copy_from_slice(&bytes[..8]);
        let mut hash = [0u8; HASH_LENGTH];
        hash.copy_from_slice(&bytes[9..]);

        Ok(Self {
            prefix: DEFAULT_PREFIX,
            salt,
            hash,
        })
    }
}

impl Display for EncryptedKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.prefix())?;
        for b in self.salt() {
            write!(f, "{:02X}", b)?;
        }
        write!(f, "{:02X}", Self::indicator())?;
        for b in self.hash() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

// Because specialisation isn't supported in Rust (yet) there's a blanket impl that prevents us simple doing
// an `impl<S: AsRef<str>> TryFrom<S> for EncryptedKey`. Unless I'm missing something of course. Hence this boilerplate.

impl TryFrom<&str> for EncryptedKey {
    type Error = EncryptedKeyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        EncryptedKey::try_convert(value)
    }
}

impl TryFrom<String> for EncryptedKey {
    type Error = EncryptedKeyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        EncryptedKey::try_convert(value)
    }
}

impl TryFrom<&String> for EncryptedKey {
    type Error = EncryptedKeyError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        EncryptedKey::try_convert(value)
    }
}

impl FromStr for EncryptedKey {
    type Err = EncryptedKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EncryptedKey::try_convert(s)
    }
}

fn constant_time_eq(a: &[u8; HASH_LENGTH], b: &[u8; HASH_LENGTH]) -> bool {
    let diff = a.iter().zip(b.iter()).fold(0u8, |acc, (&x, &y)| acc | (x ^ y));
    diff == 0
}

#[cfg(test)]
mod test {
    use crate::encrypted_key::EncryptedKey;
    use hex_literal::hex;
    use sha1::Sha1;
    use std::convert::TryFrom;

    #[test]
    fn with_salt() {
        let key = EncryptedKey::hash_with_salt("foo", hex!("85EE955FF128F012"));
        assert_eq!(
            key.to_string().as_str(),
            "16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D"
        );

        let key = EncryptedKey::hash_with_salt(
            "come_gently_into_the_night_with_a_bag_of_rabbits?!",
            hex!("72FAE4A168BFD4B9"),
        );
        assert_eq!(
            key.to_string().as_str(),
            "16:72FAE4A168BFD4B960381AF76E8204863A3A3C2FE96D48B4D6D92B9D16"
        );
    }

    #[test]
    fn from_string() {
        let key = EncryptedKey::try_from("16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D").unwrap();
        assert_eq!(key.salt(), &hex!("85EE955FF128F012"));
        assert_eq!(key.hash(), &hex!("A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D"));

        let parsed: EncryptedKey = "16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D"
            .parse()
            .unwrap();
        assert_eq!(key, parsed);

        let key = EncryptedKey::try_from("16:72FAE4A168BFD4B960381AF76E8204863A3A3C2FE96D48B4D6D92B9D16").unwrap();
        assert_eq!(key.salt(), &hex!("72FAE4A168BFD4B9"));
        assert_eq!(key.hash(), &hex!("381AF76E8204863A3A3C2FE96D48B4D6D92B9D16"));
    }

    #[test]
    fn convert_errors() {
        // Invalid start
        assert!(EncryptedKey::try_from("15:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D").is_err());
        // Wrong length
        assert!(EncryptedKey::try_from("16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2").is_err());
        assert!(EncryptedKey::try_from("16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D0").is_err());
        // Wrong indicator
        assert!(EncryptedKey::try_from("16:85EE955FF128F01261A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D").is_err());
        // Ok
        assert!(EncryptedKey::try_from("16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D").is_ok());
    }

    #[test]
    fn validate() {
        let hash = EncryptedKey::hash_password("ride the wild Pony");
        assert!(hash.validate("ride the wild Pony"));
        assert!(!hash.validate("some other password"));
    }

    #[test]
    fn hashes_full_passphrase_when_longer_than_s2k_count() {
        // Indicator 0x60 expands to count = 65536 bytes.
        // When salt (8 bytes) + secret exceeds 65536 bytes, RFC 2440 / RFC 4880
        // requires hashing the entire salt + passphrase without truncating at 65536.
        let salt = hex!("85EE955FF128F012");
        let prefix = "a".repeat(65_536);
        let secret_a = format!("{}alpha", prefix);
        let secret_b = format!("{}bravo", prefix);

        let key_a = EncryptedKey::hash_with_salt(&secret_a, salt);
        let key_b = EncryptedKey::hash_with_salt(&secret_b, salt);

        assert_ne!(key_a.hash(), key_b.hash());
        assert!(key_a.validate(&secret_a));
        assert!(!key_a.validate(&secret_b));

        let mut expected_sha = Sha1::new();
        expected_sha.update(&salt);
        expected_sha.update(secret_a.as_bytes());
        assert_eq!(key_a.hash(), &expected_sha.digest().bytes());
    }
}

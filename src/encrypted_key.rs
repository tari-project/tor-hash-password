use crate::EncryptedKeyError;
use rand::{thread_rng, RngCore};
use sha1::Sha1;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};

pub const SALT_LENGTH: usize = 8;
pub const HASH_LENGTH: usize = 20;
pub const DEFAULT_PREFIX: &str = "16";

const EXPBIAS: u8 = 6;

/// A representation of a Tor hashed pssword. See the [module docs](../lib) for more details and examples.
///
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
        self.hash == other.hash
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
        // Could be replaced by a const if indicator doesn't ever change, but leaving the door open for future changes there.
        let mut count = (16usize + (c & 15) as usize) << ((c >> 4) + EXPBIAS);

        let mut sha = Sha1::new();
        let input = [salt, secret.as_bytes()].concat();
        let secret_len = input.len();

        while count > 0 {
            if count > secret_len {
                sha.update(&input);
                count = count.saturating_sub(secret_len);
            } else {
                sha.update(&input[..count]);
                count = 0;
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

        println!("{:?}", &bytes[..8]);
        println!("{:?}", &bytes[8]);
        println!("{:?}", &bytes[9..]);
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

#[cfg(test)]
mod test {
    use crate::encrypted_key::EncryptedKey;
    use hex_literal::hex;
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
        let key =
            EncryptedKey::try_from("16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D")
                .unwrap();
        assert_eq!(key.salt(), &hex!("85EE955FF128F012"));
        assert_eq!(
            key.hash(),
            &hex!("A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D")
        );

        let key =
            EncryptedKey::try_from("16:72FAE4A168BFD4B960381AF76E8204863A3A3C2FE96D48B4D6D92B9D16")
                .unwrap();
        assert_eq!(key.salt(), &hex!("72FAE4A168BFD4B9"));
        assert_eq!(
            key.hash(),
            &hex!("381AF76E8204863A3A3C2FE96D48B4D6D92B9D16")
        );
    }

    #[test]
    fn convert_errors() {
        // Invalid start
        assert!(EncryptedKey::try_from(
            "15:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D"
        )
        .is_err());
        // Wrong length
        assert!(EncryptedKey::try_from(
            "16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2"
        )
        .is_err());
        assert!(EncryptedKey::try_from(
            "16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D0"
        )
        .is_err());
        // Wrong indicator
        assert!(EncryptedKey::try_from(
            "16:85EE955FF128F01261A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D"
        )
        .is_err());
        // Ok
        assert!(EncryptedKey::try_from(
            "16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D"
        )
        .is_ok());
    }

    #[test]
    fn validate() {
        let hash = EncryptedKey::hash_password("ride the wild Pony");
        assert!(hash.validate("ride the wild Pony"));
        assert!(!hash.validate("some other password"));
    }
}

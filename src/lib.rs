//! Tor hashed password algorithm
//!
//! Tor is controllable by making socket connections to the “ControlPort” usually on port 9051.
//!
//! .torrc requires a "HashedControlPassword" option to make use of password authentication. You can generate this
//! value by running `tor --hash-password <secret>` on the command line. This module gives you that same functionality
//! as a standalone Rust library.
//!
//! The salted hash is computed according to the S2K algorithm in RFC 2440 (OpenPGP), and prefixed with the s2k specifier.
//! This is then encoded in hexadecimal, prefixed by the indicator sequence   "16:".
//!
//! Thus, for example, the password 'foo' could encode to:
//! ```text
//!      16:660537E3E1CD4999 60 44A3BF558097A981F539FEA2F9DA662B4626C1C2
//!         ++++++++++++++++ ** ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//!            salt       indicator     hashed value
//! ```
//!
//! ## Example use
//!
//!To generate a Tor password, use `hash_password`. You can verify challenges against the hash with `verify`:
//! ```edition2018
//!use tor_hash_passwd::EncryptedKey;
//!
//! let hash = EncryptedKey::hash_password("ride the wild Pony");
//!assert!(hash.validate("ride the wild Pony"));
//!assert!(!hash.validate("some other password"));
//!
//! ```
//!
//! The algorithm uses a random salt, so generating the same hashed password multiple times will deliver different
//! hashes. To get reproducible hashes, you must supply the salt:
//!
//!```edition2018
//!use tor_hash_passwd::EncryptedKey;
//!use hex_literal::hex;
//!
//! let key = EncryptedKey::hash_with_salt("foo", hex!("85EE955FF128F012"));
//! assert_eq!(key.to_string().as_str(), "16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D");
//! ```
//!
//! You can also convert a string to an Encrypted Key:
//!
//! ```edition2018
//!# use std::convert::TryFrom;
//!# use tor_hash_passwd::EncryptedKey;
//! let key = EncryptedKey::try_from("16:85EE955FF128F01260A1CFA5C3BE947A512B8EFAD1BC410671E3DBBA2D").unwrap();
//! assert!(key.validate("foo"));
//! ```


mod encrypted_key;

pub use encrypted_key::EncryptedKey;
// Rust Codex32 Library and Reference Implementation
// Written in 2023 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! codex32 Reference Implementation
//!
//! This project is a reference implementation of BIP-XXX "codex32", a project
//! by Leon Olson Curr and Pearlwort Snead to produce checksummed and secret-shared
//! BIP32 master seeds.
//!
//! References:
//!   * BIP-XXX <https://github.com/apoelstra/bips/blob/2023-02--volvelles/bip-0000.mediawiki>
//!   * The codex32 website <https://www.secretcodex32.com>
//!   * BIP-0173 "bech32" <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
//!   * BIP-0032 "BIP 32" <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
//!

// This is the shittiest lint ever and has literally never been correct when
// it has fired, and somehow in rust-bitcoin managed NOT to fire in the one
// case where it might've been useful.
// https://github.com/rust-bitcoin/rust-bitcoin/pull/1701
#![allow(clippy::suspicious_arithmetic_impl)]

mod checksum;
mod gf32;

use std::{cmp, fmt};
pub use checksum::Engine as ChecksumEngine;
pub use gf32::Fe as Fe32;

#[derive(Debug)]
pub enum Error {
    /// Error related to a single bech32 character
    Field(gf32::Error),
    /// Identifier had wrong length when creating a share
    IdNotLength4(usize),
    /// When translating from u5 to u8, there was an incomplete group of
    /// size greater than 4 bits, meaning an entirely extraneous character.
    IncompleteGroup(usize),
    /// Tried a codex32 string of an illegal length
    InvalidLength(usize),
    /// Tried to decode a character which was not part of the bech32 alphabet,
    /// or, if in the HRP, was not ASCII.
    InvalidChar(char),
    /// Tried to decode a character but its case did not match the expected case
    InvalidCase(Case, char),
    /// String had an invalid checksum
    InvalidChecksum {
        /// Checksum we used, "long" or "short"
        checksum: &'static str,
        /// The string with the bad checksum
        string: String,
    },
    /// Threshold was not an allowed value (2 through 9, or 0)
    InvalidThreshold(char),
    /// Threshold was not an allowed value (2 through 9, or 0)
    InvalidThresholdN(usize),
    /// Share index was not an allowed value (only S if the threshold is 0,
    /// otherwise anything goes)
    InvalidShareIndex(Fe32),
    /// A set of shares to be interpolated did not all have the same length
    MismatchedLength(usize, usize),
    /// A set of shares to be interpolated did not all have the same HRP
    MismatchedHrp(String, String),
    /// A set of shares to be interpolated did not all have the same threshold
    MismatchedThreshold(usize, usize),
    /// A set of shares to be interpolated did not all have the same ID
    MismatchedId(String, String),
    /// A share index was repeated in the set of shares to interpolate.
    RepeatedIndex(Fe32),
    /// A set of shares to be interpolated did not have enough shares
    ThresholdNotPassed { threshold: usize, n_shares: usize },
}

impl From<gf32::Error> for Error {
    fn from(e: gf32::Error) -> Error {
        Error::Field(e)
    }
}

/// Lowercase or uppercase (as applied to the bech32 alphabet)
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug)]
pub enum Case {
    /// qpzr...
    Lower,
    /// QPZR...
    Upper,
}

/// A codex32 string, containing a valid checksum
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Codex32String(String);

impl fmt::Display for Codex32String {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Codex32String {
    fn sanity_check(&self) -> Result<(), Error> {
        let parts = self.parts_inner()?;
        let incomplete_group = (parts.payload.len() * 5) % 8;
        if incomplete_group > 4 {
            return Err(Error::IncompleteGroup(incomplete_group));
        }
        Ok(())
    }

    /// Construct a codex32 string from a not-yet-checksummed string
    pub fn from_unchecksummed_string(mut s: String) -> Result<Self, Error> {
        // Determine what checksum to use and extend the string
        let (len, mut checksum) = if s.len() < 81 {
            (13, checksum::Engine::new_codex32_short())
        } else {
            (15, checksum::Engine::new_codex32_long())
        };
        s.reserve_exact(len);

        // Split out the HRP
        let (hrp, real_string) = match s.rsplit_once('1') {
            Some((s1, s2)) => (s1, s2),
            None => ("", &s[..]),
        };
        // Compute the checksum
        checksum.input_hrp(hrp)?;
        checksum.input_data_str(real_string)?;
        for ch in checksum.into_residue() {
            s.push(ch.to_char());
        }

        let ret = Codex32String(s);
        ret.sanity_check()?;
        Ok(ret)
    }

    /// Construct a codex32 string from an already-checksummed string
    pub fn from_string(s: String) -> Result<Self, Error> {
        let (name, mut checksum) = if s.len() >= 48 && s.len() < 94 {
            ("short", checksum::Engine::new_codex32_short())
        } else if s.len() >= 125 && s.len() < 128 {
            ("long", checksum::Engine::new_codex32_long())
        } else {
            return Err(Error::InvalidLength(s.len()));
        };

        // Split out the HRP
        let (hrp, real_string) = match s.rsplit_once('1') {
            Some((s1, s2)) => (s1, s2),
            None => ("", &s[..]),
        };
        checksum.input_hrp(hrp)?;
        checksum.input_data_str(real_string)?;
        if !checksum.is_valid() {
            return Err(Error::InvalidChecksum {
                checksum: name,
                string: s,
            });
        }
        // Looks good, return
        let ret = Codex32String(s);
        ret.sanity_check()?;
        Ok(ret)
    }

    /// Break the string up into its constituent parts
    fn parts_inner(&self) -> Result<Parts, Error> {
        let (hrp, s) = match self.0.rsplit_once('1') {
            Some((s1, s2)) => (s1, s2),
            None => ("", &self.0[..]),
        };
        let checksum_len = if self.0.len() > 93 { 15 } else { 13 };
        let ret = Parts {
            hrp,
            threshold: match s.as_bytes()[0] {
                b'0' => 0,
                b'2' => 2,
                b'3' => 3,
                b'4' => 4,
                b'5' => 5,
                b'6' => 6,
                b'7' => 7,
                b'8' => 8,
                b'9' => 9,
                _ => return Err(Error::InvalidThreshold(s.as_bytes()[0].into())),
            },
            id: &s[1..5],
            share_index: Fe32::from_char(s.as_bytes()[5].into()).unwrap(),
            payload: &s[6..s.len() - checksum_len],
            checksum: &s[s.len() - checksum_len..],
        };
        if ret.threshold == 0 && ret.share_index != Fe32::S {
            return Err(Error::InvalidShareIndex(ret.share_index));
        }
        Ok(ret)
    }

    /// Break the string up into its constituent parts
    pub fn parts(&self) -> Parts {
        // unwrap OK since we validated the input on parse
        self.parts_inner().unwrap()
    }

    /// Interpolate a set of shares to derive a share at a specific index.
    ///
    /// Using the index `Fe32::S` will recover the master seed.
    pub fn interpolate_at(
        shares: &[Codex32String],
        target: Fe32,
    ) -> Result<Codex32String, Error> {
        // Collect indices and sanity check
        if shares.is_empty() {
            return Err(Error::ThresholdNotPassed {
                threshold: 1,
                n_shares: 0,
            });
        }
        let mut indices = Vec::with_capacity(shares.len());
        let s0_parts = shares[0].parts();
        if s0_parts.threshold > shares.len() {
            return Err(Error::ThresholdNotPassed {
                threshold: s0_parts.threshold,
                n_shares: shares.len(),
            });
        }
        for share in shares {
            let parts = share.parts();
            if shares[0].0.len() != share.0.len() {
                return Err(Error::MismatchedLength(shares[0].0.len(), share.0.len()));
            }
            if s0_parts.hrp != parts.hrp {
                return Err(Error::MismatchedHrp(s0_parts.hrp.into(), parts.hrp.into()));
            }
            if s0_parts.threshold != parts.threshold {
                return Err(Error::MismatchedThreshold(
                    s0_parts.threshold,
                    parts.threshold,
                ));
            }
            if s0_parts.id != parts.id {
                return Err(Error::MismatchedId(s0_parts.id.into(), parts.id.into()));
            }
            indices.push(parts.share_index);
        }

        // Do lagrange interpolation
        let mut mult = Fe32::P;
        for i in 0..shares.len() {
            if indices[i] == target {
                // If we're trying to output an input share, just output it directly.
                // Naive Lagrange multiplication would otherwise multiply by 0.
                return Ok(shares[i].clone());
            }

            mult *= indices[i] + target;
        }

        let payload_len = 6 + s0_parts.payload.len() + s0_parts.checksum.len();
        let hrp_len = shares[0].0.len() - payload_len;
        let mut result = vec![Fe32::Q; payload_len];

        for i in 0..shares.len() {
            let mut inv = Fe32::P;
            for j in 0..shares.len() {
                inv *= indices[j]
                    + if i == j {
                        target
                    } else {
                        // If there is a repeated index, just call this an error. Technically
                        // speaking, we could reject the other one and re-do the threshold
                        // check in case we had enough unique ones .. but easier to just make
                        // it the user's responsibility to provide unique indices to begin with.
                        if indices[i] == indices[j] {
                            return Err(Error::RepeatedIndex(indices[i]));
                        }
                        indices[i]
                    }
            }

            for (j, res_j) in result.iter_mut().enumerate() {
                let ch_at_i = char::from(shares[i].0.as_bytes()[hrp_len + j]);
                *res_j += mult / inv * Fe32::from_char(ch_at_i).unwrap();
            }
        }

        let mut s = s0_parts.hrp.to_owned();
        s.push('1');
        if s0_parts.hrp.chars().all(char::is_uppercase) {
            s.extend(
                result
                    .into_iter()
                    .map(Fe32::to_char)
                    .map(|c| c.to_ascii_uppercase()),
            );
        } else {
            s.extend(result.into_iter().map(Fe32::to_char));
        }
        Ok(Codex32String(s))
    }

    /// Creates a S share from bare seed data
    pub fn from_seed(
        hrp: &str,
        threshold: usize,
        id: &str,
        share_idx: Fe32,
        data: &[u8],
    ) -> Result<Codex32String, Error> {
        if id.len() != 4 {
            return Err(Error::IdNotLength4(id.len()));
        }

        let mut ret = String::with_capacity(hrp.len() + 6 + (data.len() * 8 + 4) / 5);
        ret.push_str(hrp);
        ret.push('1');
        let k = match threshold {
            0 => Fe32::_0,
            2 => Fe32::_2,
            3 => Fe32::_3,
            4 => Fe32::_4,
            5 => Fe32::_5,
            6 => Fe32::_6,
            7 => Fe32::_7,
            8 => Fe32::_8,
            9 => Fe32::_9,
            x => return Err(Error::InvalidThresholdN(x)),
        };
        // FIXME correct case to match HRP
        ret.push(k.to_char());
        ret.push_str(id);
        ret.push(share_idx.to_char());

        // Convert byte data to base 32
        let mut next_u5 = 0;
        let mut rem = 0;
        for byte in data {
            // Each byte provides at least one u5. Push that.
            let u5 = (next_u5 << (5 - rem)) | byte >> (3 + rem);
            ret.push(Fe32::from_u8(u5).unwrap().to_char());
            next_u5 = byte & ((1 << (3 + rem)) - 1);
            // If there were 2 or more bits from the last iteration, then
            // this iteration will push *two* u5s.
            if rem >= 2 {
                ret.push(Fe32::from_u8(next_u5 >> (rem - 2)).unwrap().to_char());
                next_u5 &= (1 << (rem - 2)) - 1;
            }
            rem = (rem + 8) % 5;
        }
        if rem > 0 {
            ret.push(Fe32::from_u8(next_u5 << (5 - rem)).unwrap().to_char());
        }

        // Initialize checksum engine with HRP and header
        let mut checksum = if data.len() < 51 {
            checksum::Engine::new_codex32_short()
        } else {
            checksum::Engine::new_codex32_long()
        };
        checksum.input_hrp(hrp)?;
        checksum.input_data_str(&ret[hrp.len() + 1..])?;
        // Now, to compute the checksum, we stick the target residue onto the end
        // of the input string, the take the resulting residue as the checksum
        checksum.input_own_target();
        ret.extend(checksum.into_residue().into_iter().map(Fe32::to_char));

        let mut checksum = checksum::Engine::new_codex32_short();
        checksum.input_hrp(hrp)?;
        checksum.input_data_str(&ret[hrp.len() + 1..])?;
        Ok(Codex32String(ret))
    }
}

/// A codex32 string, split into its constituent partrs
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Parts<'s> {
    hrp: &'s str,
    threshold: usize,
    id: &'s str,
    share_index: Fe32,
    payload: &'s str,
    checksum: &'s str,
}

impl<'s> Parts<'s> {
    /// Extract the binary data from a checksummed string
    ///
    /// If the string does not have a multiple-of-8 number of bits, right-pad the
    /// final byte with 0s.
    pub fn data(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity((self.payload.len() * 5 + 7) / 8);

        let mut next_byte = 0;
        let mut rem = 0;
        for ch in self.payload.chars() {
            let fe = Fe32::from_char(ch).unwrap(); // unwrap ok since string is valid bech32
            match rem.cmp(&3) {
                cmp::Ordering::Less => {
                    // If we are within 3 bits of the start we can fit the whole next char in
                    next_byte |= fe.to_u8() << (3 - rem);
                }
                cmp::Ordering::Equal => {
                    // If we are exactly 3 bits from the start then this char fills in the byte
                    ret.push(next_byte | fe.to_u8());
                    next_byte = 0;
                }
                cmp::Ordering::Greater => {
                    // Otherwise we have to break it in two
                    let overshoot = rem - 3;
                    assert!(overshoot > 0);
                    ret.push(next_byte | (fe.to_u8() >> overshoot));
                    next_byte = fe.to_u8() << (8 - overshoot);
                }
            }
            rem = (rem + 5) % 8;
        }
        debug_assert!(rem <= 4); // checked when parsing the string
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // hex-encoding is a niche requirement and does not belong in the standard
    // library of a systems programming language -- rust IRC
    fn hex(data: &[u8]) -> String {
        let mut ret = String::new();
        for byte in data {
            ret.push_str(&format!("{:02x}", byte));
        }
        ret
    }

    #[test]
    fn bip_vector_1() {
        let secret = "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw";
        let c32 = Codex32String::from_string(secret.into()).unwrap();
        let c32_parts = c32.parts();
        assert_eq!(c32_parts.hrp, "ms");
        // Don't test the separator "1" which is not stored anywhere
        assert_eq!(c32_parts.threshold, 0);
        assert_eq!(c32_parts.share_index, Fe32::S);
        assert_eq!(c32_parts.id, "test");
        assert_eq!(c32_parts.payload, "xxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_eq!(c32_parts.checksum, "4nzvca9cmczlw");
        assert_eq!(hex(&c32_parts.data()), "318c6318c6318c6318c6318c6318c631");
        // Don't check master node xpriv; this is implied by the master seed
        // and would require extra dependencies to compute
    }

    #[test]
    fn bip_vector_2() {
        let share_ac = [
            Codex32String::from_string("MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM".into())
                .unwrap(),
            Codex32String::from_string("MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN".into())
                .unwrap(),
        ];

        let share_d = Codex32String::interpolate_at(&share_ac, Fe32::D).unwrap();
        assert_eq!(
            share_d.to_string(),
            "MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG"
        );

        let seed = Codex32String::interpolate_at(&share_ac, Fe32::S).unwrap();
        assert_eq!(
            seed.to_string(),
            "MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW"
        );
        assert_eq!(
            hex(&seed.parts().data()),
            "d1808e096b35b209ca12132b264662a5"
        );
    }

    #[test]
    fn bip_vector_3() {
        let share_sac = [
            Codex32String::from_string("ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln".into())
                .unwrap(),
            Codex32String::from_string("ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t".into())
                .unwrap(),
            Codex32String::from_string("ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr".into())
                .unwrap(),
        ];

        let share_def = [
            Codex32String::interpolate_at(&share_sac, Fe32::D).unwrap(),
            Codex32String::interpolate_at(&share_sac, Fe32::E).unwrap(),
            Codex32String::interpolate_at(&share_sac, Fe32::F).unwrap(),
        ];
        assert_eq!(
            share_def[0].to_string(),
            "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm",
        );
        assert_eq!(
            share_def[1].to_string(),
            "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9",
        );
        assert_eq!(
            share_def[2].to_string(),
            "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704",
        );
    }

    #[test]
    fn bip_vector_4() {
        #[rustfmt::skip]
        let seed_b = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 
        ];
        let seed = Codex32String::from_seed("ms", 0, "leet", Fe32::S, &seed_b).unwrap();
        assert_eq!(
            seed.to_string(),
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma",
        );
        // Our code sticks 0s onto the bitstring to get a multiple of 5 bits. Confirm that
        // other choices would've worked.
        assert_eq!(seed.parts().data(), seed_b);
        let alt_encodings = [
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqpj82dp34u6lqtd",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqzsrs4pnh7jmpj5",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqrfcpap2w8dqezy",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqy5tdvphn6znrf0",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq9dsuypw2ragmel",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqx05xupvgp4v6qx",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq8k0h5p43c2hzsk",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqgum7hplmjtr8ks",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqf9q0lpxzt5clxq",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq28y48pyqfuu7le",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqt7ly0paesr8x0f",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqvrvg7pqydv5uyz",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqd6hekpea5n0y5j",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqwcnrwpmlkmt9dt",
            "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq0pgjxpzx0ysaam",
        ];
        for alt in alt_encodings {
            let seed = Codex32String::from_string(alt.into()).unwrap();
            assert_eq!(seed.parts().data(), seed_b);
        }
    }

    #[test]
    fn bip_vector_5() {
        let long_seed = Codex32String::from_string(
            "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK".into()
        ).unwrap();
        assert_eq!(
            hex(&long_seed.parts().data()),
            "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9",
        );
    }

    #[test]
    fn bip_invalid_bad_checksums() {
        let bad_checksums = [
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxmazxdp4sx5q",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxq70v3y94304t",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxg4m2aylswft",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxght46zhq0x4",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxl8jqrdhvqkc4",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxepvjkxnc9wu",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxcakee32853f",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxx4nknfgj6u67a",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx3n5n5gyweuvq3",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxjqllfg3pf3fv4",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxn0c66xf2j0kjn",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxh73jw8glx8fpk",
            "ms10testsyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyymjljntsznrq3mv",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0p99y5vsmt84t",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxj4r3qrklkmtsz",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx8kp950klmrlsm",
        ];
        for chk in bad_checksums {
            if let Err(Error::InvalidChecksum { .. }) = Codex32String::from_string(chk.into()) {
                // ok
            } else {
                panic!(
                    "Accepted {} with bad checksum, or raised a different error",
                    chk
                );
            }
        }

        let wrong_checksums = [
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxx372x3mkc5m8sa0q",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx82zvxjc02rt0vnl",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxyc57nnpvpcnhggt",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxf9e2wxsusjgmlws",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxdpu39xl2lkru3g4",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxqelpaxwk0jz4e",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxncdn5kjxq7grt",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxhq00y08vc7gjg",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxdckj6wn4z7r3p",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxjl32g6u3wgg8j",
        ];
        for chk in wrong_checksums {
            let err = Codex32String::from_string(chk.into());
            if let Err(Error::InvalidChecksum { .. }) = err {
                // ok
            } else if let Err(Error::InvalidLength { .. }) = err {
                // also ok
            } else {
                panic!(
                    "Accepted {} with bad checksum, or raised a different error",
                    chk
                );
            }
        }
    }

    #[test]
    fn bip_invalid_improper_length() {
        let bad_length = [
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxx8ty2gx0n6rnaa",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxus2h522w7u6vq",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxc8d60uanwukvn",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxwaaaq5yk0vfeg",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxu9cfgk0a4muxaam",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxzu2kdncfaew65ae",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpsx45vtf9n2uk5h",
            "ms12testxxxxxxxxxxxxxxxxxxxxxxxxxtn5jkk94ayuqc",
            "ms12testxxxxxxxxxxxxxxxxxxxxxxxxxxvspjygypsrrkl",
            "ms12testxxxxxxxxxxxxxxxxxxxxxxxxxxxxqmufxffdkzfac",
            "ms12testxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxmgr4z3c807ml7",
            "ms12testxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx4q3s54t8ejm8dfj",
            "ms12testxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxr0wzwtfvgh3th2",
            "ms12testxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcpkhsxdrp05hymv",
        ];
        for chk in bad_length {
            let err = Codex32String::from_string(chk.into());
            if let Err(Error::InvalidLength { .. }) = err {
                // ok
            } else if let Err(Error::IncompleteGroup(..)) = err {
                // ok
            } else {
                panic!(
                    "Accepted {} with invalid length, or raised a different error: {:?}",
                    chk, err
                );
            }
        }
    }

    #[test]
    fn bip_invalid_misc() {
        if let Err(Error::InvalidShareIndex(..)) =
            Codex32String::from_string("ms10testxxxxxxxxxxxxxxxxxxxxxxxxxxxx3wq9mzgrwag9".into())
        {
            // ok
        } else {
            panic!("bad error, expected 'invalid share index'");
        }

        if let Err(Error::InvalidThreshold(..)) =
            Codex32String::from_string("ms1testxxxxxxxxxxxxxxxxxxxxxxxxxxxxs9lz3we7s9wh4".into())
        {
            // ok
        } else {
            panic!("bad error, expected 'invalid share index'");
        }
    }

    // Skip tho "missing ms prefix" tests because this library is HRP-agnostic
    // FIXME it probably should not be, and should probably enforce the ms

    #[test]
    fn bip_invalid_case() {
        let bad_case = [
            "MS10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw",
            "ms10TESTsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw",
            "ms10testSxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw",
            "ms10testsXXXXXXXXXXXXXXXXXXXXXXXXXX4nzvca9cmczlw",
            "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4NZVCA9CMCZLW",
        ];
        for chk in bad_case {
            let err = Codex32String::from_string(chk.into());
            if let Err(Error::InvalidCase { .. }) = err {
                // ok
            } else {
                panic!(
                    "Accepted {} with invalid length, or raised a different error: {:?}",
                    chk, err
                );
            }
        }
    }
}

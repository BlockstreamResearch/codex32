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

//! Field Implementation
//!
//! Implements GF32 arithmetic, defined and encoded as in BIP-0173 "bech32"
//!

use std::{
    convert::{TryFrom, TryInto},
    fmt, num, ops, str,
};

/// Locarithm table of each bech32 element, as a power of alpha = Z.
///
/// Includes Q as 0 but this is false; you need to exclude Q because
/// it has no discrete log. If we could have a 1-indexed array that
/// would panic on a 0 index that would be better.
#[rustfmt::skip]
const LOG: [isize; 32] = [
     0,  0,  1, 14,  2, 28, 15, 22,
     3,  5, 29, 26, 16,  7, 23, 11, 
     4, 25,  6, 10, 30, 13, 27, 21,
    17, 18,  8, 19, 24,  9, 12, 20,
];

/// Mapping of powers of 2 to the numeric value of the element
#[rustfmt::skip]
const LOG_INV: [u8; 31] = [
     1,  2,  4,  8, 16,  9, 18, 13,
    26, 29, 19, 15, 30, 21,  3,  6,
    12, 24, 25, 27, 31, 23,  7, 14,
    28, 17, 11, 22,  5, 10, 20,
];

/// Mapping from numeric value to bech32 character
#[rustfmt::skip]
const CHARS_LOWER: [char; 32] = [
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8', //  +0
    'g', 'f', '2', 't', 'v', 'd', 'w', '0', //  +8
    's', '3', 'j', 'n', '5', '4', 'k', 'h', // +16
    'c', 'e', '6', 'm', 'u', 'a', '7', 'l', // +24
];

/// Mapping from bech32 character (either case) to numeric value
#[rustfmt::skip]
const CHARS_INV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
];

/// Field-related error
#[derive(Debug)]
pub enum Error {
    /// Tried to decode a GF32 element from a string, but got more than one character
    ExtraChar(char),
    /// Tried to interpret an integer as a GF32 element but it could not be
    /// converted to an u8.
    NotAByte(num::TryFromIntError),
    /// Tried to interpret a byte as a GF32 element but its numeric value was
    /// outside of [0, 32).
    InvalidByte(u8),
}

/// An element of GF32
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Fe(u8);

impl ops::Add for Fe {
    type Output = Fe;
    fn add(self, other: Fe) -> Fe {
        Fe(self.0 ^ other.0)
    }
}

impl ops::AddAssign for Fe {
    fn add_assign(&mut self, other: Fe) {
        *self = *self + other;
    }
}

// Subtraction is the same as addition in a char-2 field
impl ops::Sub for Fe {
    type Output = Fe;
    fn sub(self, other: Fe) -> Fe {
        self + other
    }
}

impl ops::SubAssign for Fe {
    fn sub_assign(&mut self, other: Fe) {
        *self = *self - other;
    }
}

impl ops::Mul for Fe {
    type Output = Fe;
    fn mul(self, other: Fe) -> Fe {
        if self.0 == 0 || other.0 == 0 {
            Fe(0)
        } else {
            let log1 = LOG[self.0 as usize];
            let log2 = LOG[other.0 as usize];
            Fe(LOG_INV[((log1 + log2) % 31) as usize])
        }
    }
}

impl ops::MulAssign for Fe {
    fn mul_assign(&mut self, other: Fe) {
        *self = *self * other;
    }
}

impl ops::Div for Fe {
    type Output = Fe;
    fn div(self, other: Fe) -> Fe {
        if self.0 == 0 {
            Fe(0)
        } else if other.0 == 0 {
            panic!("Attempt to divide {} by 0 in GF32", self);
        } else {
            let log1 = LOG[self.0 as usize];
            let log2 = LOG[other.0 as usize];
            Fe(LOG_INV[((31 + log1 - log2) % 31) as usize])
        }
    }
}

impl ops::DivAssign for Fe {
    fn div_assign(&mut self, other: Fe) {
        *self = *self / other;
    }
}

impl Fe {
    // These are a little gratuitous for a reference implementation,
    // but it makes me happy to do it
    pub const Q: Fe = Fe(0);
    pub const P: Fe = Fe(1);
    #[allow(dead_code)]
    pub const Z: Fe = Fe(2);
    pub const R: Fe = Fe(3);
    pub const Y: Fe = Fe(4);
    pub const _9: Fe = Fe(5);
    pub const X: Fe = Fe(6);
    pub const _8: Fe = Fe(7);
    pub const G: Fe = Fe(8);
    pub const F: Fe = Fe(9);
    pub const _2: Fe = Fe(10);
    pub const T: Fe = Fe(11);
    #[allow(dead_code)]
    pub const V: Fe = Fe(12);
    #[allow(dead_code)]
    pub const D: Fe = Fe(13);
    #[allow(dead_code)]
    pub const W: Fe = Fe(14);
    pub const _0: Fe = Fe(15);
    pub const S: Fe = Fe(16);
    pub const _3: Fe = Fe(17);
    #[allow(dead_code)]
    pub const J: Fe = Fe(18);
    #[allow(dead_code)]
    pub const N: Fe = Fe(19);
    pub const _5: Fe = Fe(20);
    pub const _4: Fe = Fe(21);
    pub const K: Fe = Fe(22);
    pub const H: Fe = Fe(23);
    pub const C: Fe = Fe(24);
    pub const E: Fe = Fe(25);
    pub const _6: Fe = Fe(26);
    pub const M: Fe = Fe(27);
    #[allow(dead_code)]
    pub const U: Fe = Fe(28);
    pub const A: Fe = Fe(29);
    pub const _7: Fe = Fe(30);
    pub const L: Fe = Fe(31);

    /// Iterator over all field elements, in alphabetical order
    pub fn iter_alpha() -> impl Iterator<Item = Fe> {
        [
            Fe::A, Fe::C, Fe::D, Fe::E, Fe::F, Fe::G, Fe::H, Fe::J,
            Fe::K, Fe::L, Fe::M, Fe::N, Fe::P, Fe::Q, Fe::R, Fe::S,
            Fe::T, Fe::U, Fe::V, Fe::W, Fe::X, Fe::Y, Fe::Z, Fe::_0,
            Fe::_2, Fe::_3, Fe::_4, Fe::_5, Fe::_6, Fe::_7, Fe::_8, Fe::_9,
        ].iter().copied()
    }

    /// Creates a field element from an integer type
    pub fn from_u8(byte: u8) -> Result<Fe, super::Error> {
        if byte < 32 {
            Ok(Fe(byte))
        } else {
            Err(super::Error::Field(Error::InvalidByte(byte)))
        }
    }

    /// Creates a field element from an integer type
    pub fn from_int<I>(i: I) -> Result<Fe, super::Error>
    where
        I: TryInto<u8, Error = num::TryFromIntError>,
    {
        i.try_into()
            .map_err(|e| super::Error::Field(Error::NotAByte(e)))
            .and_then(Self::from_u8)
    }

    /// Creates a field element from a single bech32 character
    pub fn from_char(c: char) -> Result<Fe, super::Error> {
        let byte = i8::try_from(u32::from(c)).map_err(|_| super::Error::InvalidChar(c))?;
        let byte = byte as u8; // cast guaranteed to be ok since we started with an unsigned value
        let u5 =
            u8::try_from(CHARS_INV[usize::from(byte)]).map_err(|_| super::Error::InvalidChar(c))?;
        Ok(Fe(u5))
    }

    /// Converts the field element to a lowercase bech32 character
    pub fn to_char(self) -> char {
        // casting and indexing fine as we have self.0 in [0, 32) as an invariant
        CHARS_LOWER[self.0 as usize]
    }

    /// Converts the field element to a 5-bit u8, with bits representing the coefficients
    /// of the polynomial representation.
    pub fn to_u8(self) -> u8 {
        self.0
    }
}

impl fmt::Display for Fe {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.to_char(), f)
    }
}

/// We abuse `UpperHex` in this library to display notably non-hex field elements
/// in uppercase.
impl fmt::UpperHex for Fe {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.to_char().to_ascii_uppercase(), f)
    }
}

impl str::FromStr for Fe {
    type Err = super::Error;
    fn from_str(s: &str) -> Result<Fe, super::Error> {
        let mut chs = s.chars();
        match (chs.next(), chs.next()) {
            (Some(c), None) => Fe::from_char(c),
            (Some(_), Some(c)) => Err(super::Error::Field(Error::ExtraChar(c))),
            (None, _) => Err(super::Error::InvalidLength(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_string() {
        let s: String = (0..32).map(Fe).map(Fe::to_char).collect();
        assert_eq!(s, "qpzry9x8gf2tvdw0s3jn54khce6mua7l");
    }

    #[test]
    fn translation_wheel() {
        // 1. Produce the translation wheel by multiplying
        let logbase = Fe(20);
        let mut init = Fe(1);
        let mut s = String::new();
        for _ in 0..31 {
            s.push(init.to_char());
            init *= logbase;
        }
        // Can be verified against the multiplication disk, starting with P and moving
        // clcockwise
        assert_eq!(s, "p529kt3uw8hlmecvxr470na6djfsgyz");

        // 2. By dividing
        let logbase = Fe(20);
        let mut init = Fe(1);
        let mut s = String::new();
        for _ in 0..31 {
            s.push(init.to_char());
            init /= logbase;
        }
        // Same deal, but counterclockwise
        assert_eq!(s, "pzygsfjd6an074rxvcemlh8wu3tk925");
    }

    #[test]
    fn recovery_wheel() {
        // Remarkably, the recovery wheel can be produced in the same way as the
        // multiplication wheel, though with a different log base and with every
        // element added by S.
        //
        // We spent quite some time deriving this, but honestly we probably could've
        // just guessed it if we'd known a priori that a wheel existed.
        let logbase = Fe(10);
        let mut init = Fe(1);
        let mut s = String::new();
        for _ in 0..31 {
            s.push((init + Fe(16)).to_char());
            init *= logbase;
        }
        // To verify, start with 3 and move clockwise on the Recovery Wheel
        assert_eq!(s, "36xp78tgk9ldaecjy4mvh0funwr2zq5");
    }
}

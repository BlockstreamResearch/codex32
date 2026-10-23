-- Copyright (c) 2025 Blockstream
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.

-- | Module for Linear Feedback Shift Registers
-- Synthesize of LFSRs.

module Codex32.Lfsr
 ( LFSR
 , lfsrLength
 , Poly, connection
 , synthesize, generate
 , validate
 ) where

import Control.Comonad
import Data.Foldable
import Data.List
import Data.Stream.Infinite (Stream(..))
import qualified Data.Stream.Infinite as Stream

import Codex32.Polynomial

-- The contents of an LFSR.  The only reason the coefficents and values are paired up is because an LFSR has equal number of coefficents and initial values.
data LFSRDatum a = LFSRDatum { coef :: a, value :: a }

-- | A linear feedback shift register, including initial values.
newtype LFSR a = LFSR [LFSRDatum a]

-- | Length of a 'LFSR'.
lfsrLength :: LFSR a -> Int
lfsrLength (LFSR l) = length l

-- | The connection polynomial of a 'LFSR'.
-- The degree of the connection polynomial is at most 'lfsrLength'.
--
-- Note: the resulting polynomials may not be normalized and may have trailing zeros.
connection :: Num a => LFSR a -> Poly a
connection (LFSR l) = 1 : map coef l

-- | Generate an infinite stream of values from an 'LFSR', including the initial values from the 'LFSR'
generate :: Num a => LFSR a -> Stream a
generate (LFSR l) = result
 where
  len = length l
  result = Stream.prepend (map value l) (extend (f . reverse . Stream.take len) result)
  f = generateNext (map coef l)

-- Interpret the coefficents from an LFSR and a (reversed) segment of the input values to generate the next value.
generateNext :: Num a => [a] -> [a] -> a
generateNext coef val = negate . sum $ zipWith (*) coef val

-- | Given a sequence of values, find a minimal 'LFSR' that 'generate's that sequence.
synthesize :: (Foldable f, Eq a, Fractional a) => f a -> LFSR a
synthesize l = LFSR (zipWith LFSRDatum coef l')
 where
  l' = toList l
  (coef, _) = synthesizeRec (reverse l')

-- The Berlekamp-Massey Algorithm.
-- Given a reversed list of inputs, recursively compute the set of coefficents of a minimal 'LFSR' to generate that input,
-- paired with a helper set of coefficents used for updating the 'LFSR' for more inputs.
synthesizeRec :: (Eq a, Fractional a) => [a] -> ([a], [a])
synthesizeRec [] = ([], [0])
synthesizeRec (n:ns) = (next, nextAdj)
 where
  (coef, adjustment) = synthesizeRec ns
  discrepency = n - generateNext coef ns
  next | 0 == discrepency = coef
       | otherwise = zipSum coef (map ((-discrepency)*) adjustment)
  nextAdj | length next == length coef = 0:adjustment
          | otherwise = map (/ discrepency) (1:coef)

-- Similar to zip (+), but instead returns the longer of the two lists instead of the shorter of the two lists.
zipSum [] l = l
zipSum l [] = l
zipSum (a:as) (b:bs) = (a + b):(zipSum as bs)

-- | Checks to see of 'synthesize' correctly produces a minimal 'lsfrLength' 'LFSR' for the given input.
validate :: (Eq a, Fractional a) => [a] -> Bool
validate l = all sound lfsrs && zero (head lfsrs) && and (zipWith complete lfsrs (tail lfsrs))
 where
  lfsrs = [(x, length x, generate lfsr, lfsrLength lfsr) | x <- inits l, let lfsr = synthesize x]
  sound (x, _, output, _) = x == Stream.take (length x) output
  zero (_, _, _, n) = 0 == n
  complete (_, _, outputN, n) (l, lenM, _, m)
    | extending = m == n
    | otherwise = m == n `max` (lenM - n)
   where
    extending = l == Stream.take lenM outputN

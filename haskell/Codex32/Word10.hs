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

module Codex32.Word10 where

import Data.List (find)
import Data.Ratio (numerator, denominator)

import Codex32.Word5
import Codex32.Polynomial

-- Word10 a b denotes the value a + b*zeta where zeta is a primitive cube root of unity and zeta^2 = zeta + 1.
data Word10 = Word10 Word5 Word5 deriving Eq

zeta = Word10 0 1
toWord10 x = Word10 x 0
conj (Word10 a b) = Word10 (a + b) b

minPoly :: Word10 -> Monic Word5
minPoly (Word10 x 0) = [x]
minPoly x = [y, z]
 where
  Word10 y 0 = x + conj x
  Word10 z 0 = x * conj x

instance Show Word10 where
  show (Word10 a b) | 0 == b = show a
                    | 0 == a && 1 == b = "zeta"
                    | 0 == a = shows b $ "*zeta"
                    | 1 == b = shows a $ " + zeta"
                    | otherwise = shows a . showString " + " . shows b $ "*zeta"

instance Num Word10 where
  Word10 a0 b0 + Word10 a1 b1 = Word10 (a0 + a1) (b0 + b1)
  a - b = a + b
  Word10 a0 b0 * Word10 a1 b1 = Word10 (a0 * a1 + b0 * b1) (a0 * b1 + a1 * b0 + b0 * b1)
  abs = error "abs{Word10}"
  signum = error "sign{Word10}"
  fromInteger = toWord10 . fromInteger

instance Fractional Word10 where
  fromRational x = fromInteger (numerator x) / fromInteger (denominator x)
  recip (Word10 a b) = Word10 ((a + b)*den) (b * den)
   where
    den = recip $ a^2 + b^2 + a*b

allWord10 = Word10 <$> allWord5 <*> allWord5

order x = find p divisors
 where
  -- divisors of 1024-1
  divisors = [1, 3, 11, 31, 33, 93, 341, 1023]
  p i = x^i == 1

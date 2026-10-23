-- Copyright (c) 2017 Marko Bencun
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

module Codex32.Word5 where

import qualified Data.Array as Arr
import Data.Word (Word8)
import Data.Ratio (numerator, denominator)
import Data.Ix (Ix, inRange, index, range)
import Data.Char (toUpper)
import Data.Bits ((.&.), shiftL, testBit, xor)
import Data.List (foldl')

newtype Word5 = UnsafeWord5 Word8 deriving (Eq, Ord)

instance Ix Word5 where
  range (UnsafeWord5 m, UnsafeWord5 n) = map UnsafeWord5 $ range (m, n)
  index (UnsafeWord5 m, UnsafeWord5 n) (UnsafeWord5 i) = index (m, n) i
  inRange (m,n) i = m <= i && i <= n

word5 :: Integral a => a -> Word5
word5 x = UnsafeWord5 ((fromIntegral x) .&. 31)

fromWord5 :: Num a => Word5 -> a
fromWord5 (UnsafeWord5 x) = fromIntegral x

-- 'alpha' is a generator for GF(32).
alpha :: Word5
alpha = word5 2

charset :: Arr.Array Word5 Char
charset = Arr.listArray (UnsafeWord5 0, UnsafeWord5 31) "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

charsetMap :: Char -> Either Char Word5
charsetMap c = maybe (Left c) Right $ lookup upperC assocs
  where
    upperC = toUpper c
    assocs = swap <$> Arr.assocs charset
    swap (a, b) = (toUpper b, a)

instance Show Word5 where
  show w = (charset Arr.! w):[]

instance Read Word5 where
  readsPrec _ [] = []
  readsPrec _ (c:cs) = [(w,cs) | Right w <- [charsetMap c]]

(.+.) :: Word5 -> Word5 -> Word5
(UnsafeWord5 x) .+. (UnsafeWord5 y) = UnsafeWord5 (x `xor` y)

(.*.) :: Word5 -> Word5 -> Word5
x .*. (UnsafeWord5 y) = foldl' (.+.) (word5 0) $ zipWith f [0..5] (iterate alphaShift x)
 where
  alphaShift (UnsafeWord5 w) | testBit w 4 = word5 (shiftL w 1 `xor` 9)
                             | otherwise = word5 (shiftL w 1)
  f i xi | testBit y i = xi
         | otherwise = word5 0

instance Num Word5 where
  (+) = (.+.)
  (-) = (.+.)
  (*) = (.*.)
  abs x | x == 0 = 0
        | otherwise = 1
  signum x = x
  fromInteger i | even i = word5 0
                | otherwise = word5 1

instance Fractional Word5 where
  fromRational x = fromInteger (numerator x) / fromInteger (denominator x)
  recip x = x ^ 30

fromString str = traverse charsetMap str
toString l = (charset Arr.!) <$> l
toChar w = charset Arr.! w

allWord5 = Arr.indices charset

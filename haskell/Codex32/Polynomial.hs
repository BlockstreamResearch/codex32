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
module Codex32.Polynomial where

-- Polynomials in little endian order.
type Poly a = [a]

horner :: (Num a) => Poly a -> a -> a
horner l x = foldr f 0 l
 where
  f c y = y*x + c

polySum :: (Num a) => Poly a -> Poly a -> Poly a
polySum [] l = l
polySum l [] = l
polySum (a:p) (b:q) = (a + b):polySum p q

polyMult :: (Num a) => Poly a -> Poly a -> Poly a
polyMult [] q = []
polyMult (a:p) q = polySum ((a*) <$> q) (fromInteger 0 : polyMult p q)

-- | Formal derivative
diff :: (Num a) => Poly a -> Poly a
diff = zipWith (*) (fromInteger <$> [1..]) . tail

-- Monic polynomials in big endian order with the leading 1 coefficent stripped.
type Monic x = [x]

monicMult :: (Eq x, Num x) => Monic x -> Monic x -> Monic x
monicMult a b = let (1:c) = reverse $ polyMult (reverse (1:a)) (reverse (1:b)) in c

-- | List of all x^i `mod` modulus
polyPowers :: (Num a) => Monic a -> [Poly a]
polyPowers modulus = reverse <$> iterate f i
 where
  i = replicate (length modulus - 1) 0 ++ [1]
  f (hd:tl) = zipWith (+) (tl ++ [0]) ((hd *) <$> modulus)

polyMod :: (Num a) => Poly a -> Monic a -> Poly a
poly `polyMod` modulus = foldr polySum [] (zipWith f poly (polyPowers modulus))
 where
  f c xp = (c *) <$> xp

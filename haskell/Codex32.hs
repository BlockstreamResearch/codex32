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
module Codex32 where

import Control.Monad (guard)
import Data.Maybe (fromMaybe, listToMaybe)
import Data.Word (Word8)
import Data.Char (isAlpha, isDigit, isLower, isUpper, toLower)
import Data.Bits (testBit)

import Codex32.Polynomial
import Codex32.Word5
import Codex32.Word10

fromBytes :: [Word8] -> [Word5]
fromBytes bytes = go $ bits ++ replicate ((negate (length bits)) `mod` 5) False
  where
    bits = bytes >>= \b -> [testBit b i | i <- [7,6..0]]
    go [] = []
    go (a:b:c:d:e:l) = w:go l
     where
      w = sum $ zipWith f [a,b,c,d,e] (word5 <$> [16, 8, 4, 2, 1])
      f True v = v
      f False v = 0

toBytes :: [Word5] -> [Word8]
toBytes l = go $ bits
  where
    bits = l >>= \(UnsafeWord5 b) -> [testBit b i | i <- [4,3..0]]
    go (a:b:c:d:e:f:g:h:l) = w:go l
     where
      w = sum $ zipWith fn [a,b,c,d,e,f,g,h] [128, 64, 32, 16, 8, 4, 2, 1]
      fn True v = v
      fn False v = 0
    go _ = []

hrpExpand str = [1] ++ [word5 (fromEnum x `div` 32) | x <- str] ++ [0] ++ [word5 (fromEnum x) | x <- str]

-- Specification of BCH code of degree 2 over GF[32]
data Spec = Spec { specPrefix :: String -- Must be lowercase
                 , specBase :: Word10
                 , specFcr :: Int -- First consecutive root
                 , specDistance :: Int
                 , specTarget :: [Word5] -- Must be have length equal to specDegree.
                 }
specHrp = hrpExpand . specPrefix
specLength spec = fromMaybe err (order (specBase spec))
 where
  err = error "Codex32.specLength: zero base"
specDataLength spec = specLength spec - specDegree spec
specRoots spec = [specBase spec^(i + specFcr spec) | i <- [0..specDistance spec-1]]
specGenerator spec = foldr1 monicMult (minPoly <$> specRoots spec)
specBias :: Spec -> Poly Word5
specBias = reverse . specTarget
specDegree = length . specGenerator

residue :: Spec -> [Word5] -> Poly Word5
residue spec body = p `polyMod` generator
 where
  generator = specGenerator spec
  p = reverse $ specHrp spec ++ body

codex32Prefix = "ms"
codex32Spec :: Spec
codex32Spec = Spec { specPrefix = codex32Prefix
                   , specBase = Word10 0 (read "G")
                   , specFcr = 77
                   , specDistance = 8
                   , specTarget = fromRight (fromString "secretshare32")
                   }

codex32LongSpec :: Spec
codex32LongSpec = Spec { specPrefix = codex32Prefix
                       , specBase = Word10 (read "E") (read "X")
                       , specFcr = 1019
                       , specDistance = 8
                       , specTarget = fromRight (fromString "secretshare32ex")
                       }

decodeErrString :: String -> Maybe (String, [Either Char Word5])
decodeErrString str | (all isLower `or` all isUpper) (filter isAlpha str) && Just '1' == listToMaybe xiferp = return (prefix, body)
                    | otherwise = Nothing
 where
  (ydob, xiferp) = break (=='1') (reverse (toLower <$> str))
  prefix = reverse $ tail xiferp
  body = charsetMap <$> reverse ydob
  or p q x = p x || q x

decodeCodex32 str = do
  (pre, body) <- decodeErrString str
  guard $ pre == codex32Prefix
  let spec = if length body <= specLength codex32Spec then codex32Spec else codex32LongSpec
  return (spec, body)

decodeString :: String -> Maybe (String, [Word5])
decodeString str = do
  (pre, errBody) <- decodeErrString str
  body <- traverse (either (const Nothing) Just) errBody
  return (pre, body)

createGenericChecksum spec = \dat -> residue spec (dat ++ target)
 where
  hrp = hrpExpand (specPrefix spec)
  generator = specGenerator spec
  target = specTarget spec

createGenericString spec = \dat -> prefix ++ "1" ++ toString (dat ++ reverse (createGenericChecksum spec dat))
 where
  prefix = specPrefix spec


createCodex32Checksum l = createGenericChecksum spec l
 where
  spec | length l <= specDataLength codex32Spec = codex32Spec
       | otherwise = codex32LongSpec

verifyGenericChecksum spec l | length l <= specLength spec = bias == residue spec l
                             | otherwise = False
 where
  hrp = hrpExpand (specPrefix spec)
  generator = specGenerator spec
  bias = specBias spec

verifyCodex32Checksum l = any (flip verifyGenericChecksum l) [codex32Spec, codex32LongSpec]

verifyGenericString spec str = (Just True ==) $ do
  (pre, dat) <- decodeString str
  guard $ pre == specPrefix spec
  return $ verifyGenericChecksum spec dat

verifyCodex32String str = (Just True ==) $ do
  (pre, dat) <- decodeString str
  guard $ pre == codex32Prefix
  return $ verifyCodex32Checksum dat

bip173Spec :: Spec
bip173Spec = Spec { specPrefix = "bc"
                  , specBase = Word10 (read "H") (read "F")
                  , specFcr = 997
                  , specDistance = 3
                  , specTarget = fromRight (fromString "qqqqqp")
                  }
bip350Spec :: Spec
bip350Spec = bip173Spec { specTarget = fromRight (fromString "4usv9r") }

fromRight (Right x) = x
fromRight (Left _) = error "Program error: fromRight: Left"

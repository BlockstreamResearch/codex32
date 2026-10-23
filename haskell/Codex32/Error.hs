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
module Codex32.Error where

import Control.Applicative ((<|>))
import Control.Monad (guard)
import Data.Either (isLeft)
import Data.List (findIndices)

import Codex32
import Codex32.Lfsr
import qualified Codex32.Linear as Linear
import Codex32.Polynomial
import Codex32.Word10
import Codex32.Word5

-- Find all roots of a given function.
solveWord10 :: (Eq a, Num a) => (Word10 -> a) -> [Word10]
solveWord10 f = filter (\x -> f x == 0) allWord10

-- Short convolution of two lists of numbers.
-- convolution [a_0..a_n] [b_0..b_m] is [c_n..c_m]
-- where c_i = a_0*b_i + ... + a_n*b_(i-n).
-- Note: the second list must be at least as long as first list for the result to be non-empty.
convolution :: Num a => [a] -> [a] -> [a]
convolution as bs  = go (reverse as) bs
 where
  go [] _ = repeat 0
  go (a:as) bs = zipWith (+) ((a *) <$> bs) (go as (tail bs))

-- Compute the error locator polynomial from a sequence of syndromes, given the erassure polynomial.
-- Note: The resulting locator polynomial doesn't include the given erasures.
-- To compute the full locator polynomial you will need to multiply the result by the given erasure polynomial.
locatorPoly :: [Word10] -> Poly Word10 -> Poly Word10
locatorPoly syndromes erasurePoly = connection (synthesize modifiedSyndromes)
  where
   modifiedSyndromes = convolution erasurePoly syndromes

-- Given erasure locations and the residue, run the BCH error correction algorithm returning the location and error values for those locations.
-- This can find up to (specDistance spec - length erasureIx)/2 error locations in addition to the given erasure locations.
-- Returns Nothing when error correction fails.
-- Returns Just [] when given a zero checksumError and empty erasuresIxs.
-- The length of the checksumError must be equal to the (specDegree spec)
bchErrorCorrections :: Spec -> [Int] -> [Word5] -> Maybe [(Int, Word5)]
bchErrorCorrections spec erasureIxs residue = do
  guard $ length erasureIxs <= length betas
  guard $ length locator == 1 + length roots
  corrections <- sequence [correct i l | i<-reverse [0..specLength spec-1], let l = recip (beta^i), l `elem` (roots ++ erasureRoots)]
  return corrections
 where
  generator = specGenerator spec
  fcr = specFcr spec
  beta = specBase spec
  betas = specRoots spec
  erasureRoots = (\i -> recip (beta^i)) <$> erasureIxs
  erasurePoly = foldr polyMult [1] [[-r, 1]|r <- erasureRoots]
  locator = locatorPoly syn erasurePoly
  checksumError = zipWith (-) residue (specBias spec)
  syn = horner (toWord10 <$> checksumError) <$> betas
  fullLocator = locator `polyMult` erasurePoly
  omega = take (length betas) $ syn `polyMult` fullLocator
  roots = solveWord10 $ horner locator
  correct i invR = do
    guard (0 == z)
    return $ (i, e)
   where
    Word10 e z = negate (horner omega invR * (invR^(fcr - 1) / horner (diff fullLocator) invR))

-- This error correctly algorithm can only correct erasures.
-- However, unlike bchErrorCorrection it sometimes (but not always) correct up to (specDegree spec) many erasures.
-- In particular it can always correct up to (specDegree spec) many erasures if they are all consecutive (a burst error).
-- Returns Nothing when error correction fails.
-- Returns Just [] when given a zero checksumError and empty erasuresIxs.
-- The length of the checksumError must be equal to the (specDegree spec)
linearErrorCorrections :: Spec -> [Int] -> [Word5] -> Maybe [(Int, Word5)]
linearErrorCorrections spec erasureIxs residue = do
  Right solution <- return $ Linear.solver unknowns checksumError
  return $ zip erasureIxs solution
 where
  checksumError = zipWith (-) residue (specBias spec)
  powers = polyPowers (specGenerator spec)
  unknowns = map (powers!!) erasureIxs

-- Tries both the bchErrorCorrections and the linearErrorCorrections.
errorCorrections :: Spec -> [Int] -> [Word5] -> Maybe [(Int, Word5)]
errorCorrections spec erasureIxs residue = bchErrorCorrections spec erasureIxs residue
                                       <|> linearErrorCorrections spec erasureIxs residue

-- Given an alledged codex32 string, attempt to find the closest string that is a valid codex32 string.
-- Returns Nothing if the implementation is unable to find a solution
correctCodex32String :: String -> Maybe String
correctCodex32String str = do
  (spec, body) <- decodeCodex32 str
  let erasureIxs = findIndices isLeft (reverse body)
  let zeroedBody = either (const 0) id <$> body
  corrections <- errorCorrections spec erasureIxs (residue spec zeroedBody)
  let corrected = foldr polySum (reverse zeroedBody) (expand <$> corrections)
  guard $ length corrected == length body
  return $ (specPrefix spec) ++ "1" ++ (toString . reverse $ corrected)
 where
  expand (i,e) = replicate i 0 ++ [e]

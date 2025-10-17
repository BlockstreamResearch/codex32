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
module Codex32.Linear where

import Data.List (findIndex, transpose)

iden :: (Num a) => Int -> [[a]]
iden 1 = [[1]]
iden n = (1:replicate (n-1) 0):((0:) <$> iden (n-1))

u `dot` v = foldr (+) 0 $ zipWith (*) u v

matrixApply m v = fmap (`dot` v) m

matrixInv :: (Fractional a, Eq a) => [[a]] -> [[a]]
matrixInv m = drop size <$> foldr clearRow augment [0..size-1]
  where
    size = length m
    augment = zipWith (++) m (iden size)
    clearRow n m | c /= 0 = fmap clear pre ++ [newRow] ++ fmap clear post
                 | otherwise = clearRow n $ row : pre ++ post
     where
      (pre, row:post) = splitAt n m
      c = recip $ m !! n !! n
      newRow = fmap (c *) row
      clear r = zipWith (-) r $ fmap (s *) newRow
        where
          s = r !! n

-- Precondition: all lists of mat have the same length
reducedRowEchelon :: (Fractional a, Eq a) => [[a]] -> [[a]]
reducedRowEchelon mat | all null mat = mat
               | any null mat = error "Linear.reducedRowEchelon: input not a matrix"
               | otherwise =
  case pivot of
    Nothing -> map (0:) (reducedRowEchelon (map tail mat))
    Just ix -> let (a,b) = splitAt ix mat in process (b++a)
 where
  pivot = findIndex (\w -> head w /= 0) mat
  process (w0:wn) = w0'':recurse
   where
    reduce w = zipWith (-) w (map (* (head w)) w0')
    w0' = map (/ (head w0)) w0
    wn' = map (tail . reduce) wn
    recurse = map (0:) (reducedRowEchelon wn')
    w0'' = foldr backsubst w0' recurse
    backsubst v w = zipWith (-) w (map (* scale) v)
     where
      scale = case filter (\(vn,_wn) -> vn /= 0) (zip v w) of
        [] -> 0
        (vi, wi):_ -> wi / vi

rank mat = length (filter (not . allZero) (reducedRowEchelon mat))
 where
  allZero = all (==0)

independent mat = length mat == rank mat

dependent mat = not (independent mat)

data SolverError = Unsolvable | MultipleSolutions
  deriving Show

-- precondition, target and every member of vecs must have equal length
-- Trys to prove that target is in the span of vec by giving a set of coefficents to be applied to vec.
-- If target is not in the span, Unsolvable is returned.
-- If the solution is not unique, MultipleSolutions is returned.
solver :: (Fractional a, Eq a) => [[a]] -> [a] -> Either SolverError [a]
solver vecs target | min n (redRank reduced) < redRank unaugmented = error "Linear.solver: Internal Error"
                   | redRank unaugmented < redRank reduced = Left Unsolvable
                   | redRank unaugmented < n = Left MultipleSolutions
                   | otherwise = Right (take n solution)
 where
  n = length vecs
  augmented = transpose (vecs ++ [target])
  reduced = reducedRowEchelon augmented
  (unaugmented, solution) = (map init reduced, map last reduced)
  redRank m = length (filter (not . all (==0)) m)

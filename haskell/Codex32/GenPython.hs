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
module GenPython where

import Data.List (foldl', intercalate)
import Data.Char (toUpper)
import qualified Numeric

import Codex32
import Polynomial
import Word5
import Word10

hrp = specHrp codex32Spec
beta = specBase codex32Spec
betas = specRoots codex32Spec
generator = specGenerator codex32Spec -- word5 <$> [25, 27, 17, 8, 0, 25, 25, 25, 31, 27, 24, 16, 16]
genLength = specLength codex32Spec
target = specTarget codex32Spec

gamma = specBase codex32LongSpec
gammas = specRoots codex32LongSpec
longGenerator = specGenerator codex32LongSpec
longTarget = specTarget codex32LongSpec

powers = iterate (alpha*) 1
genPowers gen = [map (a*) gen | a <- powers]
pack l = foldl' f 0 l
  where
    f x a = 2^5 * x + fromWord5 a

showHex n = "0x" ++ Numeric.showHex n ""

printPython long target gen hrp = do
  putStrLn $ const ++ " = " ++ showHex (pack target)
  putStrLn ""
  putStrLn $ "def ms32_" ++ long ++ "polymod(values):"
  putStrLn $ "  GEN = [" ++ intercalate ", " (showHex . pack <$> take 5 (genPowers gen)) ++ "]"
  putStrLn $ "  residue = " ++ (showHex . pack $ hrp)
  putStrLn $ "  for v in values:"
  putStrLn $ "    b = (residue >> " ++ show (5 * (length gen - 1)) ++ ")"
  putStrLn $ "    residue = (residue & " ++ showHex (2 ^ (5 * (length gen - 1)) - 1) ++ ") << 5 ^ v"
  putStrLn $ "    for i in range(5):"
  putStrLn $ "      residue ^= GEN[i] if ((b >> i) & 1) else 0"
  putStrLn $ "   return residue"
  putStrLn ""
  putStrLn $ "def ms32_verify_" ++ long ++ "checksum(data):"
  putStrLn $ "  return ms32_" ++ long ++ "polymod(data) == " ++ const
  putStrLn ""
  putStrLn $ "def ms32_create_" ++ long ++ "checksum(data):"
  putStrLn $ "  values = data"
  putStrLn $ "  polymod = ms32_" ++ long ++ "polymod(values + [0] * " ++ show (length gen) ++ ") ^ " ++ const
  putStrLn $ "  return [(polymod >> 5 * (" ++ show (length gen - 1) ++ " - i)) & 31 for i in range(" ++ show (length gen) ++ ")]"
 where
  const = "MS32_" ++ (toUpper <$> long) ++ "CONST"

main | checks = do
  printPython "" target generator hrp
  putStrLn ""
  printPython "long_" longTarget longGenerator hrp
 where
  checks = length generator == length target
        && length longGenerator == length longTarget

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
module TestVectors where

import Data.Char (toUpper)
import Data.List (inits, tails)

import Codex32
import Codex32.Polynomial
import Codex32.Word5
import Codex32.Word10

validExamples =
  [ "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw"
  , "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM"
  , "MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN"
  , "MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG"
  , "MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW"
  , "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln"
  , "ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t"
  , "ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr"
  , "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm"
  , "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9"
  , "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704"
  , "ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r"
  , "ms13cashsllhdmn9m42vcsamx24zrxgs3qzfatvdwq5692k6"
  , "ms13cashsllhdmn9m42vcsamx24zrxgs3qrsx6ydhed97jx2"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqpj82dp34u6lqtd"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqzsrs4pnh7jmpj5"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqrfcpap2w8dqezy"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqy5tdvphn6znrf0"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq9dsuypw2ragmel"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqx05xupvgp4v6qx"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq8k0h5p43c2hzsk"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqgum7hplmjtr8ks"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqf9q0lpxzt5clxq"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq28y48pyqfuu7le"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqt7ly0paesr8x0f"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqvrvg7pqydv5uyz"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqd6hekpea5n0y5j"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqwcnrwpmlkmt9dt"
  , "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq0pgjxpzx0ysaam"
  , "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK"
  ]

createString prefix target generator dat = prefix ++ "1" ++ toString (dat ++ reverse checksum)
 where
  hrp = hrpExpand prefix
  checksum = reverse (hrp ++ dat ++ target) `polyMod` generator

prefix = specPrefix codex32Spec
roots = specRoots codex32Spec
generator = specGenerator codex32Spec
target = specTarget codex32Spec
longRoots = specRoots codex32LongSpec
longGenerator = specGenerator codex32LongSpec
longTarget = specTarget codex32LongSpec

badIdentity = "faux"
invalidA = [ createString prefix target generator l
           | target <- [ replicate (length generator) 0, replicate (length generator - 1) 0 ++ [1] ]
           , let Right l = fromString $ "0" ++ badIdentity ++ "s" ++ replicate 26 'x'
           ]
        ++ [ createString prefix (reverse bias) g l
           | g <- badGens
           , let bias = reverse target `polyMod` g
           , let Right l = fromString $ "0" ++ badIdentity ++ "s" ++ replicate (26 + 13 - length g) 'x'
           ]
        ++ [ createString prefix target generator l
           | spec <- [ bip173Spec, bip350Spec ]
           , let target = specTarget spec
           , let generator = specGenerator spec
           , let Right l = fromString $ "0" ++ badIdentity ++ "s" ++ replicate (28 + 13 - length generator) 'x'
           ]
 where
  badGens = foldr1 monicMult . fmap minPoly <$> zipWith (<>) (init $ inits roots) (tail <$> tails roots)

invalidB = [ createString prefix target longGenerator l
           | target <- [ replicate (length longGenerator) 0, replicate (length longGenerator - 1) 0 ++ [1] ]
           , let Right l = fromString $ "0" ++ badIdentity ++ "s" ++ replicate 103 'x'
           ]
        ++ [ createString prefix (reverse bias) g l
           | g <- badLongGens
           , let bias = reverse longTarget `polyMod` g
           , let Right l = fromString $ "0" ++ badIdentity ++ "s" ++ replicate (103 + 15 - length g) 'x'
           ]
 where
  badLongGens = foldr1 monicMult . fmap minPoly <$> zipWith (<>) (init $ inits longRoots) (tail <$> tails longRoots)

invalidC = [ createString prefix (if long then longTarget else target) (if long then longGenerator else generator) l
           | sz <- [24, 26, 72, 73, 74, 75, 76, 77, 103, 105]
           , let long = sz <= 74
           , let Right l = fromString $ "0" ++ badIdentity ++ "s" ++ replicate sz 'x'
           ]

invalidD = [ createString prefix (if long then longTarget else target) (if long then longGenerator else generator) l
           | (threshold, share) <- [("0", "s"), ("2", "x")]
           , sz <- [24, 25, 27, 73, 75, 102, 104]
           , let long = 75 <= sz
           , let Right l = fromString $ threshold ++ badIdentity ++ share ++ replicate sz 'x'
           ]

invalidE = [ createString prefix target generator l
           | Right l <- [ fromString $ "0" ++ badIdentity ++ "x" ++ replicate 26 'x'
                       , fromString $ badIdentity ++ "xx" ++ replicate 26 'x'
                       ]
           ]

invalidF = [ str, "1"++str,"ms"++str,"m1"++str,"s1"++str] ++ [tail badHrp] ++ badHrps
 where
  Right l = fromString $ "0" ++ badIdentity ++ "s" ++ replicate 26 'x'
  'm':'s':'1':str = createString prefix target generator l
  badHrps@(badHrp:_) = [ createString prefix target generator l | prefix <- ["", "m", "s"] ]

invalidG = [ zipWith ($) adj str
           | adj <- [ [ if i `elem` uppers then toUpper else id | i <- [0..]]
                    | uppers <- [[0],[1],[0,1],[4..7],[8],[9..34],[35..47]]
                    ]
           ]
 where
  Right l = fromString $ "0" ++ badIdentity ++ "s" ++ replicate 26 'x'
  str = createString prefix target generator l

invalidExamples = concat [invalidA, invalidB, invalidC, invalidD, invalidE, invalidF, invalidG]

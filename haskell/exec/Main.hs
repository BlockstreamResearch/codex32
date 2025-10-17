module Main where

import Control.Applicative ((<**>), (<|>), many)
import Control.Arrow ((+++))
import Control.Monad (unless)
import Data.List (find,intercalate, nub)
import Data.Monoid ((<>))
import Data.Text (pack)
import qualified Options.Applicative as Opt
import qualified Options.Applicative.Types as Opt
import qualified Prettyprinter as PP
import qualified Prettyprinter.Util as PP
import qualified System.Exit as Sys

import Codex32
import Codex32.Error
import Codex32.Word5
import Codex32.Polynomial

data AdvancedOptions = AdvancedOptions { optLength :: Int
                                       , optOverrideLength :: Bool
                                       , optErasures :: [Int]
                                       , optResidue :: Poly Word5
                                       }

data Command = Simple String
             | Advanced AdvancedOptions

residueReader :: Opt.ReadM [Word5]
residueReader = Opt.eitherReader parse
 where
  parse = (errMsg +++ reverse) . fromString
  errMsg c = "Illegal Bech32 character " ++ show c ++ "."

codex32SimpleParser :: Opt.Parser Command
codex32SimpleParser = Simple <$> Opt.strArgument (Opt.metavar "CODEX32_STRING" <> Opt.help "Codex32 string to correct")

codex32AdvancedParser :: Opt.Parser Command
codex32AdvancedParser = Advanced <$>
  (AdvancedOptions <$> Opt.option Opt.auto (Opt.long "len" <> Opt.metavar metaLength <> Opt.help "Total length of codex32 string")
                   <*> Opt.switch (Opt.long overrideOptName <> Opt.hidden)
                   <*> many (Opt.option Opt.auto (Opt.short 'e' <> Opt.metavar "ERASURE_LOCATION" <> Opt.help "Location of unreadable character (can be repeated)"))
                   <*> Opt.argument residueReader (Opt.metavar metaResidue <> Opt.help "Residue from worksheet"))

metaLength = "LENGTH"
overrideOptName = "override_length"
metaResidue = "RESIDUE"

codex32CorrectParser :: Opt.ParserInfo Command
codex32CorrectParser = Opt.info ((codex32SimpleParser <|> codex32AdvancedParser) <**> Opt.helper) (Opt.progDescDoc desc)
 where
  pretty = PP.reflow . pack
  desc = Just $ pretty "Error correct codex32 strings."
             <> PP.line <> PP.line
             <> pretty "Pass an 'ms1' string on the command line to try and output an error-corrected version of that string."
             <> PP.line <> PP.line
             <> pretty "Alternatively, if you are verifying your checksum using the worksheet from the Codex32 booklet, you can pass '--len 48' followed by the 13 character residue you computed on your worksheet."
             <> PP.space <> PP.space
             <> pretty "If you have unreadable characters in your string, use your best guess and add '-e <location>' to let the tool know which box contained your unreadable character."
             <> PP.space <> PP.space
             <> pretty "If error correction is possible, the program will output instructions on which character locations contain errors and what values to add, using the booklet's addition wheel, in order to correct the error."
             <> PP.space <> PP.space
             <> pretty "With this method, the computer can help you correct your codex32 string without even needing to know what the string is."

codex32CorrectOptions :: Opt.Parser Command
codex32CorrectOptions = Opt.subparser (Opt.command "correct" codex32CorrectParser)

codex32Options :: Opt.ParserInfo Command
codex32Options = Opt.info (codex32CorrectOptions <**> Opt.helper) mempty

codex32Prefs :: Opt.ParserPrefs
codex32Prefs = Opt.prefs Opt.showHelpOnEmpty

formatCorrections :: Int -> [(Int, Word5)] -> String
formatCorrections _ [] = "No errors found.  Residue is correct."
formatCorrections len corrections = unlines (header : (fmt <$> corrections))
 where
  header = show (length corrections) ++ " errors found.  Make the following corrections."
  fmt (ix, delta) = "Add " ++ show (toChar delta) ++ " to position " ++ show (len - ix) ++ "."

main :: IO ()
main = Opt.customExecParser codex32Prefs codex32Options >>= run

run :: Command -> IO a
run (Simple codex32Str) =
  case (correctCodex32String codex32Str) of
    Nothing -> putStrLn "Failed to error correct string" >> Sys.exitFailure
    Just str -> putStrLn str >> Sys.exitSuccess
run (Advanced options) | bitsize < 128 = failWith $ metaLength ++ " too short."
                       | 512 < bitsize = failWith $ metaLength ++ " too long."
                       | degree /= length residue = failWith $ metaResidue ++ " must be " ++ show degree ++ " characters for length " ++ show len ++ "."
                       | not (optOverrideLength options) && bitsize `notElem` [128, 160, 192, 224, 256, 512] = failWith $ "Unusual bitsize found.  Override with --" ++ overrideOptName ++ "."
                       | specLength spec < dataLength || 5 <= padding = failWith $ "Invalid " ++ metaLength ++ "."
                       | degree < length erasureIxs = failWith $ "No more than "++ show degree ++ "-e options are allowed."
                         -- erasureIxs are negated from the parsed values, so that is why these messages seem backwards, but they are not.
                       | any (< 0) erasureIxs = failWith $ "Erasure locations cannot be greater than "++ show len ++"."
                       | any (dataLength <=) erasureIxs = failWith $ "Erasure locations must be after the prefix."
                       | otherwise = format result
 where
  erasureIxs = (len -) <$> (nub (optErasures options))
  residue = optResidue options
  len = optLength options
  spec | 99 <= len = codex32LongSpec
       | otherwise = codex32Spec
  degree = specDegree spec
  dataLength = len - length (specPrefix spec) - 1
  payloadLength = dataLength - 6 - length (specTarget spec)
  (bytesize, padding) = (payloadLength * 5) `divMod` 8
  bitsize = bytesize * 8
  failWith str = Opt.handleParseResult . Opt.Failure $ Opt.parserFailure codex32Prefs codex32Options (Opt.ErrorMsg str) [Opt.Context "correct" codex32CorrectParser]
  result = errorCorrections spec erasureIxs residue
  format Nothing = putStrLn "Too many errors.  Unable to correct." >> Sys.exitFailure
  format (Just corrections) = putStr (formatCorrections len corrections) >> Sys.exitSuccess

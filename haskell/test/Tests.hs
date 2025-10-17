module Main where

import Control.Monad (guard, replicateM)
import Data.Char (toLower)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.QuickCheck (Gen, Property, chooseInt, elements, forAll, shuffle, testProperty)

import Codex32
import Codex32.Error
import Codex32.Word5
import TestVectors

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests"
    [ testProperty "prop_verifyCodex32Checksum_valid" prop_verifyCodex32Checksum_valid
    , testProperty "prop_correctCodex32String_BCHError" prop_correctCodex32String_BCHError
    , testProperty "prop_correctCodex32String_LinearError" prop_correctCodex32String_LinearError
    ]

-- :TODO: actually generate arbitrary valid data
arbitraryValid :: Gen String
arbitraryValid = elements validExamples

correctableBCHErrorVector :: Spec -> Int -> Gen [Maybe Word5]
correctableBCHErrorVector spec length = do
  (errorCount, erasureCount) <- elements distribution
  let remainderCount = length - errorCount - erasureCount
  errorString <- replicateM errorCount genError
  let erasureString = replicate erasureCount Nothing
  let remainderString = replicate remainderCount 0
  shuffle $ erasureString ++ fmap Just (errorString ++ remainderString)
 where
  distance = specDistance spec
  distribution = do
    errorCount <- [0..distance `div` 2]
    erasureCount <-[0..distance-2*errorCount]
    guard (0 < errorCount || 0 < erasureCount)
    return (errorCount, erasureCount)
  genError = word5 <$> chooseInt (1,31)

correctableLinearErrorVector :: Spec -> Int -> Gen [Maybe Word5]
correctableLinearErrorVector spec length = do
  start <- chooseInt (0,length - degree)
  return $ replicate start (Just 0) ++ replicate degree Nothing ++ replicate (length - degree - start) (Just 0)
 where
  degree = specDegree spec

arbitraryError :: (Spec -> Int -> Gen [Maybe Word5]) -> Gen (String, String)
arbitraryError mkError = do
  valid <- arbitraryValid
  let Just (spec, body) = decodeCodex32 valid
  err <- mkError spec (length body)
  let errBody = zipWith addError body err
  let errString = specPrefix spec ++ "1" ++ errBody
  return (toLower <$> valid, errString)
 where
  addError _ Nothing = '?'
  addError (Left _) _ = '?'
  addError (Right v) (Just e) = toChar (v + e)

prop_verifyCodex32Checksum_valid :: Property
prop_verifyCodex32Checksum_valid = forAll arbitraryValid verifyCodex32String

correctable (valid, errString) = Just valid == correctCodex32String errString

prop_correctCodex32String_BCHError :: Property
prop_correctCodex32String_BCHError = forAll (arbitraryError correctableBCHErrorVector) correctable

prop_correctCodex32String_LinearError :: Property
prop_correctCodex32String_LinearError = forAll (arbitraryError correctableLinearErrorVector) correctable

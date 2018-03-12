{-# LANGUAGE OverloadedStrings #-}

import qualified Codec.Crypto.RSA as RSA
import qualified Crypto.Cipher.AES as AESmod
import Crypto.Random
import Crypto.Random.AESCtr
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.UTF8 as BU8
import Data.Maybe
import Numeric
import System.Crypto.Pkcs11 as P
import System.Crypto.Pkcs11.Attribs as A
import qualified System.Crypto.Pkcs11.Lazy as PL
import System.Environment
import Test.HUnit

-- generateKey :: Library -> BU8.ByteString -> String -> IO (ObjectHandle, ObjectHandle)
-- generateKey lib pin label = do
--     withSession lib 0 True $ \sess -> do
--         login sess User pin
--         generateKeyPair sess RsaPkcsKeyPairGen [ModulusBits 2048, Label label, Token True] [Label label, Token True]
defaultPin = BU8.fromString "123abc_"

withSessionT lib slotId f =
  withSession False lib slotId $ \sess -> do
    login sess User defaultPin
    f sess

testAesExtractableKeyGeneration lib slotId =
  withSessionT lib slotId $ \sess -> do
    aesKeyHandle <-
      generateKey
        (simpleMech AesKeyGen)
        [ ValueLen 16
        , A.Label "testaeskey"
        , Extractable True
        , Modifiable True
        , UnwrapTemplate []
        ]
        sess
    extractable <- getExtractable aesKeyHandle
    modifiable <- getModifiable aesKeyHandle
    keyType <- getKeyType aesKeyHandle
    classAttr <- getAttrib ClassType aesKeyHandle
    labelAttr <- getAttrib LabelType aesKeyHandle
    valueAttr <- getAttrib ValueType aesKeyHandle
    getBoolAttr PrivateType aesKeyHandle
    getBoolAttr CheckValueType aesKeyHandle
    getBoolAttr DeriveType aesKeyHandle
    getBoolAttr LocalType aesKeyHandle
    getBoolAttr NeverExtractableType aesKeyHandle
    getBoolAttr AlwaysSensitiveType aesKeyHandle
    keyGenMechAttr <- getAttrib KeyGenMechanismType aesKeyHandle
    getBoolAttr WrapWithTrustedType aesKeyHandle
    unwrapTemplAttr <- getAttrib UnwrapTemplateType aesKeyHandle
    getAttrib IdType aesKeyHandle
    getAttrib StartDateType aesKeyHandle
    getAttrib EndDateType aesKeyHandle
    getTokenFlag aesKeyHandle
    getPrivateFlag aesKeyHandle
    getSensitiveFlag aesKeyHandle
    getEncryptFlag aesKeyHandle
    getDecryptFlag aesKeyHandle
    getWrapFlag aesKeyHandle
    getUnwrapFlag aesKeyHandle
    getSignFlag aesKeyHandle
    getVerifyFlag aesKeyHandle
    assertEqual "Class type should be SecretKey" (Class SecretKey) classAttr
    assertEqual "Key type should be AES" AES keyType
    assertEqual "Key gen mech should be AesKeyGen" (A.KeyGenMechanism AesKeyGen) keyGenMechAttr
    assertBool "Extractable attribute should be true" extractable
    assertBool "Modifiable attribute should be true" modifiable
    assertEqual "Label should be equal to testaeskey" (A.Label "testaeskey") labelAttr
    assertEqual "Unwrap template should be empty" (A.UnwrapTemplate []) unwrapTemplAttr
    let clearText = BS.pack [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    encData <- encrypt (simpleMech AesEcb) aesKeyHandle clearText Nothing
    decData <- decrypt (simpleMech AesEcb) aesKeyHandle encData Nothing
    assertEqual "Decrypted data does not match original" clearText decData

testRsa lib slotId =
  withRWSession lib slotId $ \sess -> do
    login sess User defaultPin
    (pubKeyHandle, privKeyHandle) <-
      generateKeyPair
        (simpleMech RsaPkcsKeyPairGen)
        [ModulusBits 2048]
        []
        sess
    -- Test signing using PKCS#1 v1.5 mode with SHA256
    swPubKey <- RSA.PublicKey 256 <$> getModulus pubKeyHandle <*> getPublicExponent pubKeyHandle
    let signedData = "hello"
    signature <- sign (simpleMech Sha256RsaPkcs) privKeyHandle signedData Nothing
    assertBool "RSA verification should succeed" $ RSA.rsassa_pkcs1_v1_5_verify RSA.hashSHA256 swPubKey (BSL.fromStrict signedData) (BSL.fromStrict signature)
    pkcsVerRes <- verify (simpleMech Sha256RsaPkcs) pubKeyHandle signedData signature
    assertBool "Signature verification should succeed using pkcs11 validation" pkcsVerRes

    -- Test encryption/decryption using PKCS#1 v1.5 mode
    rng <- newGenIO :: IO SystemRandom
    let (encryptedBlob, _) = RSA.encryptPKCS rng swPubKey (BSL.fromStrict clearText)
        clearText = "cleartext"
    dec <- decrypt (simpleMech RsaPkcs) privKeyHandle (BSL.toStrict encryptedBlob) Nothing
    assertEqual "Decrypted RSA data should match clear text" clearText dec


oldtest lib slotId = do
  info <- getInfo lib
  slotInfo <- getSlotInfo lib slotId
  tokenInfo <- getTokenInfo lib slotId
  mechanisms <- getMechanismList lib slotId 100
  mechInfo <- getMechanismInfo lib slotId RsaPkcsKeyPairGen
  withRWSession lib slotId $ \sess -> do
    login sess SecurityOfficer defaultPin
    initPin sess "testpin"
    logout sess
    setPin sess "testpin" defaultPin
    sessInfo <- getSessionInfo sess
    login sess User defaultPin
    aesKeyHandle <-
      generateKey (simpleMech AesKeyGen) [ValueLen 16, Token True, A.Label "testaeskey", Extractable True] sess
    let original = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    encData <- PL.encrypt (simpleMech AesEcb) aesKeyHandle (BSL.pack original)
    decData <- decrypt (simpleMech AesEcb) aesKeyHandle (BSL.toStrict encData) Nothing
    assertEqual "Decrypted data should match original" decData (BS.pack original)
    lazyDecData <- PL.decrypt (simpleMech AesEcb) aesKeyHandle encData
    assertEqual "Decrypted data should match original" (BSL.toStrict lazyDecData) (BS.pack original)
    (pubKeyHandle, privKeyHandle) <-
      generateKeyPair
        (simpleMech RsaPkcsKeyPairGen)
        [ModulusBits 2048, Token True, A.Label "key"]
        [Token True, A.Label "key"]
        sess
    wrappedAesKey <- wrapKey (simpleMech RsaPkcs) pubKeyHandle aesKeyHandle Nothing
    unwrappedAesKey <- unwrapKey (simpleMech RsaPkcs) privKeyHandle wrappedAesKey [Class SecretKey, KeyType AES]
    randData <- generateRandom sess 10
    setAttributes aesKeyHandle [Extractable False]
    aesKeySize <- getObjectSize aesKeyHandle
    copiedObjHandle <- copyObject aesKeyHandle []
    destroyObject aesKeyHandle
    digestedData <- digest (simpleMech Sha256) sess (BS.replicate 16 0) Nothing
    createdAesKey <- createObject sess [Class SecretKey, KeyType AES, Value (BS.replicate 16 0)]
    dhParamsHandle <- generateKey (simpleMech DhPkcsParameterGen) [PrimeBits 512] sess
    dhPrime <- getPrime dhParamsHandle
    dhBase <- getBase dhParamsHandle
    (ecPubKey, ecPrivKey) <-
      generateKeyPair (simpleMech EcKeyPairGen) [EcParams (B64.decodeLenient "BggqhkjOPQMBBw==")] [] sess
    derEcPoint <- getEcPoint ecPubKey
    derEcParams <- getEcdsaParams ecPubKey
    let signedData = "hello"
    ecSignature <- sign (simpleMech Ecdsa) ecPrivKey signedData Nothing
    ecVerifyRes <- verify (simpleMech Ecdsa) ecPubKey signedData ecSignature
    assertBool "Signature verification should succeed" ecVerifyRes
  withROSession lib slotId $ \sess -> do
    login sess User defaultPin
    objects <- findObjects sess [Class PrivateKey, A.Label "key"]
    let objId = head objects
    mod <- getModulus objId
    pubExp <- getPublicExponent objId
    rng <- newGenIO :: IO SystemRandom
    let pubKey = RSA.PublicKey 256 mod pubExp
        aesKeyBs = BS.pack [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        (encKey, rng') = RSA.encryptPKCS rng pubKey (BSL.fromStrict aesKeyBs)
        aesKey = AESmod.initAES aesKeyBs
        clearText = "hello00000000000"
        encryptedMessage = AESmod.encryptECB aesKey clearText
    unwrappedKey <- unwrapKey (simpleMech RsaPkcs) objId (BSL.toStrict encKey) [Class SecretKey, KeyType AES]
    decAes <- decrypt (simpleMech AesEcb) unwrappedKey encryptedMessage Nothing
    assertEqual "Decrypted data should match original clear text" clearText decAes

main = do
  softHsmPath <- lookupEnv "SOFTHSM_PATH"
  putStrLn "Loading PKCS11 library"
  lib <- loadLibrary $ fromMaybe "/usr/local/lib/softhsm/libsofthsm2.so" softHsmPath
  putStrLn $ "cryptoki version = " ++ show (libraryVersion lib)
  allSlotsNum <- getSlotNum lib True
  slots <- getSlotList lib True (fromIntegral allSlotsNum)
  let slotId = head slots
  let pin = defaultPin
  putStrLn $ "Using slot with id: " ++ show slotId
  putStrLn "Initializing token"
  initToken lib slotId pin "test-token"
  withRWSession lib slotId $ \sess -> do
    login sess SecurityOfficer pin
    initPin sess pin
  let tests =
        TestList
          [ "Test AES key generation and encryption" ~: TestCase (testAesExtractableKeyGeneration lib slotId)
          , TestCase (oldtest lib slotId)
          , "Test RSA key generation and operations" ~: TestCase (testRsa lib slotId)
          ]
  runTestTT tests
  releaseLibrary lib
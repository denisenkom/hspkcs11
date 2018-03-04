{-# LANGUAGE OverloadedStrings #-}

import qualified Codec.Crypto.RSA as RSA
import qualified Crypto.Cipher.AES as AESmod
import Crypto.Random
import Crypto.Random.AESCtr
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.UTF8 as BU8
import Numeric
import System.Crypto.Pkcs11 as P
import qualified System.Crypto.Pkcs11.Lazy as PL
import Test.HUnit

-- generateKey :: Library -> BU8.ByteString -> String -> IO (ObjectHandle, ObjectHandle)
-- generateKey lib pin label = do
--     withSession lib 0 True $ \sess -> do
--         login sess User pin
--         generateKeyPair sess RsaPkcsKeyPairGen [ModulusBits 2048, Label label, Token True] [Label label, Token True]
defaultPin = BU8.fromString "123abc_"

withSessionT lib slotId f = do
  withSession False lib slotId $ \sess -> do
    login sess User defaultPin
    f sess

testAesExtractableKeyGeneration lib slotId = do
  withSessionT lib slotId $ \sess -> do
    aesKeyHandle <- generateKey (simpleMech AesKeyGen) [ValueLen 16, P.Label "testaeskey", Extractable True] sess
    let clearText = BS.pack [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    encData <- encrypt (simpleMech AesEcb) aesKeyHandle clearText Nothing
    decData <- decrypt (simpleMech AesEcb) aesKeyHandle encData Nothing
    assertEqual "Decrypted data does not match original" clearText decData

oldtest lib slotId = do
  info <- getInfo lib
  putStrLn (show info)
  allSlotsNum <- getSlotNum lib False
  putStrLn ("total number of slots: " ++ show allSlotsNum)
  slots <- getSlotList lib True 2
  putStrLn ("slots: " ++ show slots)
  putStrLn "getSlotInfo"
  slotInfo <- getSlotInfo lib slotId
  putStrLn (show slotInfo)
  putStrLn "getTokenInfo"
  tokenInfo <- getTokenInfo lib slotId
  putStrLn (show tokenInfo)
  putStrLn "getMechanismList"
  mechanisms <- getMechanismList lib slotId 100
  putStrLn $ show mechanisms
  mechInfo <- getMechanismInfo lib slotId RsaPkcsKeyPairGen
  putStrLn $ show mechInfo
    --putStrLn "generating key"
    --(pubKeyHandle, privKeyHandle) <- generateKey lib defaultPin "key"
    --putStrLn (show pubKeyHandle)
  putStrLn "open writable session"
  withRWSession lib slotId $ \sess -> do
    putStrLn "login as SO"
    login sess SecurityOfficer defaultPin
    putStrLn "init token pin"
    initPin sess "testpin"
    putStrLn "logout"
    logout sess
    putStrLn "setPin"
    setPin sess "testpin" defaultPin
    putStrLn "getSessionInfo"
    sessInfo <- getSessionInfo sess
    putStrLn $ show sessInfo
    login sess User defaultPin
    putStrLn "generate key"
    aesKeyHandle <-
      generateKey (simpleMech AesKeyGen) [ValueLen 16, Token True, P.Label "testaeskey", Extractable True] sess
    putStrLn $ "generated key " ++ (show aesKeyHandle)
    putStrLn "encryption"
    encryptInit (simpleMech AesEcb) aesKeyHandle
    encData <- PL.encrypt sess (BSL.pack [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    putStrLn $ show encData
    putStrLn "decryption"
    decData <- decrypt (simpleMech AesEcb) aesKeyHandle (BSL.toStrict encData) Nothing
    putStrLn $ show decData
    putStrLn "generating key pair"
    (pubKeyHandle, privKeyHandle) <-
      generateKeyPair
        (simpleMech RsaPkcsKeyPairGen)
        [ModulusBits 2048, Token True, P.Label "key"]
        [Token True, P.Label "key"]
        sess
    putStrLn $ "generated " ++ (show pubKeyHandle) ++ " and " ++ (show privKeyHandle)
    putStrLn "wrap key"
    wrappedAesKey <- wrapKey (simpleMech RsaPkcs) pubKeyHandle aesKeyHandle Nothing
    putStrLn $ show wrappedAesKey
    putStrLn "unwrap key"
    unwrappedAesKey <- unwrapKey (simpleMech RsaPkcs) privKeyHandle wrappedAesKey [Class SecretKey, KeyType AES]
    putStrLn "sign"
    let signedData = BS.pack [0, 0, 0, 0]
    signature <- sign (simpleMech RsaPkcs) privKeyHandle signedData Nothing
    putStrLn $ show signature
        --putStrLn "get operation state"
        --operState <- getOperationState sess 1000
        --putStrLn $ show operState
    putStrLn "verify"
    verRes <- verify (simpleMech RsaPkcs) pubKeyHandle signedData signature
    putStrLn $ "verify result " ++ (show verRes)
        --putStrLn "signRecoverInit"
        --signRecoverInit (simpleMech Rsa9796) sess privKeyHandle
    putStrLn "seedRandom"
    seedRandom sess signedData
    putStrLn "generateRandom"
    randData <- generateRandom sess 10
    putStrLn $ show randData
    putStrLn "set attributes"
    setAttributes aesKeyHandle [Extractable False]
    putStrLn "get object size"
    aesKeySize <- getObjectSize aesKeyHandle
    putStrLn $ show $ fromIntegral aesKeySize
    putStrLn "copy object"
    copiedObjHandle <- copyObject aesKeyHandle []
    putStrLn $ show copiedObjHandle
    putStrLn "deleting object"
    destroyObject aesKeyHandle
    putStrLn "digest"
    digestedData <- digest (simpleMech Sha256) sess (BS.replicate 16 0) Nothing
    putStrLn $ show digestedData
    putStrLn "create object"
    createdAesKey <- createObject sess [Class SecretKey, KeyType AES, Value (BS.replicate 16 0)]
    putStrLn $ show createdAesKey
    putStrLn "generate DH domain parameters"
    dhParamsHandle <- generateKey (simpleMech DhPkcsParameterGen) [PrimeBits 512] sess
    dhPrime <- getPrime dhParamsHandle
    dhBase <- getBase dhParamsHandle
    putStrLn $ "generated DH prime=" ++ (show dhPrime) ++ " base=" ++ (show dhBase)
        --putStrLn "generate DH PKCS key pair"
        --(pubKeyHandle, privKeyHandle) <- generateKeyPair sess (simpleMech DhPkcsKeyPairGen) [Prime dhPrime, Base dhBase] []
        --putStrLn $ "generated key " ++ (show pubKeyHandle)
        --putStrLn "deriving DH key"
        --deriveKey sess (simpleMech DhPkcsDerive) privKeyHandle []
    putStrLn "generating EC key pair using prime256v1"
    (ecPubKey, ecPrivKey) <-
      generateKeyPair (simpleMech EcKeyPairGen) [EcParams (B64.decodeLenient "BggqhkjOPQMBBw==")] [] sess
    derEcPoint <- getEcPoint ecPubKey
    derEcParams <- getEcdsaParams ecPubKey
    putStrLn $ "EC point DER=" ++ (show $ B64.encode derEcPoint) ++ " params DER=" ++ (show $ B64.encode derEcParams)
    putStrLn "signing with ECDSA"
    ecSignature <- sign (simpleMech Ecdsa) ecPrivKey signedData Nothing
    putStrLn $ show ecSignature
    putStrLn "verifying signature"
    ecVerifyRes <- verify (simpleMech Ecdsa) ecPubKey signedData ecSignature
    putStrLn $ show ecVerifyRes
  putStrLn "close all sessions"
  closeAllSessions lib slotId
  putStrLn "open read-only session"
  withROSession lib slotId $ \sess -> do
    putStrLn "token login"
    login sess User defaultPin
    objects <- findObjects sess [Class PrivateKey, P.Label "key"]
    putStrLn $ show objects
    let objId = head objects
    getTokenFlag objId
    getPrivateFlag objId
    getSensitiveFlag objId
        --getEncryptFlag objId
    decryptFlag <- getDecryptFlag objId
        --getWrapFlag objId
    getUnwrapFlag objId
    signFlag <- getSignFlag objId
    mod <- getModulus objId
    pubExp <- getPublicExponent objId
    putStrLn $ show decryptFlag
    putStrLn $ show signFlag
    putStrLn $ showHex mod ""
    putStrLn $ showHex pubExp ""
    rng <- newGenIO :: IO SystemRandom
    let pubKey = RSA.PublicKey 256 mod pubExp
        aesKeyBs = BS.pack [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        (encKey, rng') = RSA.encryptPKCS rng pubKey (BSL.fromStrict aesKeyBs)
        --pubObjects <- findObjects sess [Class PublicKey, Label "key"]
        --let pubKeyObjId = head pubObjects
        --encText <- encrypt RsaPkcs sess pubKeyObjId "hello"
        --putStrLn $ show encText
        --let encTextLen = BS.length encText
        --putStrLn $ show encTextLen
    unwrappedKey <- unwrapKey (simpleMech RsaPkcs) objId (BSL.toStrict encKey) [Class SecretKey, KeyType AES]
    let aesKey = AESmod.initAES aesKeyBs
        encryptedMessage = AESmod.encryptECB aesKey "hello00000000000"
        -- test decryption using RSA key
    dec <- decrypt (simpleMech RsaPkcs) objId (BSL.toStrict encKey) Nothing
    putStrLn $ show dec
        -- test decryption using AES key
    decAes <- decrypt (simpleMech AesEcb) unwrappedKey encryptedMessage Nothing
    putStrLn $ show decAes
    logout sess

main = do
  putStrLn "Loading PKCS11 library"
  lib <- loadLibrary "/usr/local/Cellar/softhsm/2.3.0/lib/softhsm/libsofthsm2.so"
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
          ]
  runTestTT tests
  releaseLibrary lib
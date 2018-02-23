{-# LANGUAGE OverloadedStrings #-}
import qualified Data.ByteString.UTF8 as BU8
import System.Crypto.Pkcs11
import Crypto.Random
import Crypto.Random.AESCtr
import qualified Codec.Crypto.RSA as RSA
import qualified Crypto.Cipher.AES as AESmod
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Numeric


-- generateKey :: Library -> BU8.ByteString -> String -> IO (ObjectHandle, ObjectHandle)
-- generateKey lib pin label = do
--     withSession lib 0 True $ \sess -> do
--         login sess User pin
--         generateKeyPair sess RsaPkcsKeyPairGen [ModulusBits 2048, Label label, Token True] [Label label, Token True]



main = do
    lib <- loadLibrary "/usr/local/Cellar/softhsm/2.3.0/lib/softhsm/libsofthsm2.so"
    info <- getInfo lib
    putStrLn(show info)
    slots <- getSlotList lib True 10
    putStrLn("slots: " ++ show slots)
    let slotId = head slots

    putStrLn "getSlotInfo"
    slotInfo <- getSlotInfo lib slotId
    putStrLn(show slotInfo)

    putStrLn "getTokenInfo"
    tokenInfo <- getTokenInfo lib slotId
    putStrLn(show tokenInfo)

    putStrLn "getMechanismList"
    mechanisms <- getMechanismList lib slotId 100
    putStrLn $ show mechanisms

    mechInfo <- getMechanismInfo lib slotId RsaPkcsKeyPairGen
    putStrLn $ show mechInfo

    putStrLn "initToken"
    initToken lib slotId (BU8.fromString "123abc_") "label"

    --putStrLn "generating key"
    --(pubKeyHandle, privKeyHandle) <- generateKey lib (BU8.fromString "123abc_") "key"
    --putStrLn (show pubKeyHandle)

    putStrLn "open writable session"
    withSession lib slotId True $ \sess -> do
        putStrLn "login as SO"
        login sess SecurityOfficer (BU8.fromString "123abc_")
        putStrLn "init token pin"
        initPin sess "testpin"
        putStrLn "logout"
        logout sess
        putStrLn "setPin"
        setPin sess "testpin" "123abc_"
        putStrLn "getSessionInfo"
        sessInfo <- getSessionInfo sess
        putStrLn $ show sessInfo
        login sess User (BU8.fromString "123abc_")
        putStrLn "generate key"
        keyHandle <- generateKey sess AesKeyGen [ValueLen 16, Token True, Label "testaeskey"]
        putStrLn $ "generated key " ++ (show keyHandle)
        putStrLn "encryption"
        encData <- encrypt AesEcb sess keyHandle (BS.pack [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
        putStrLn $ show encData
        putStrLn "decryption"
        decData <- decrypt AesEcb sess keyHandle encData
        putStrLn $ show decData
        putStrLn "deleting object"
        destroyObject sess keyHandle
        putStrLn "generating key pair"
        (pubKeyHandle, privKeyHandle) <- generateKeyPair sess RsaPkcsKeyPairGen [ModulusBits 2048, Token True, Label "key"] [Token True, Label "key"]
        putStrLn $ "generated " ++ (show pubKeyHandle) ++ " and " ++ (show privKeyHandle)
        putStrLn "signInit"
        signInit sess (simpleMech RsaPkcs) privKeyHandle
        putStrLn "sign"
        let signedData = BS.pack [0,0,0,0]
        signature <- sign sess signedData 1000
        putStrLn $ show signature
        putStrLn "verifyInit"
        verifyInit sess (simpleMech RsaPkcs) pubKeyHandle
        putStrLn "verify"
        verRes <- verify sess signedData signature
        putStrLn $ "verify result " ++ (show verRes)

    putStrLn "open read-only session"
    withSession lib slotId False $ \sess -> do
        putStrLn "token login"
        login sess User (BU8.fromString "123abc_")
        objects <- findObjects sess [Class PrivateKey, Label "key"]
        putStrLn $ show objects
        let objId = head objects
        getTokenFlag sess objId
        getPrivateFlag sess objId
        getSensitiveFlag sess objId
        --getEncryptFlag sess objId
        decryptFlag <- getDecryptFlag sess objId
        --getWrapFlag sess objId
        getUnwrapFlag sess objId
        signFlag <- getSignFlag sess objId
        mod <- getModulus sess objId
        pubExp <- getPublicExponent sess objId
        putStrLn $ show decryptFlag
        putStrLn $ show signFlag
        putStrLn $ showHex mod ""
        putStrLn $ showHex pubExp ""
        rng <- newGenIO :: IO SystemRandom
        let pubKey = RSA.PublicKey 256 mod pubExp
            aesKeyBs = BS.pack [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            (encKey, rng') = RSA.encryptPKCS rng pubKey (BSL.fromStrict aesKeyBs)
        --pubObjects <- findObjects sess [Class PublicKey, Label "key"]
        --let pubKeyObjId = head pubObjects
        --encText <- encrypt RsaPkcs sess pubKeyObjId "hello"
        --putStrLn $ show encText
        --let encTextLen = BS.length encText
        --putStrLn $ show encTextLen
        unwrappedKeyHandle <- unwrapKey RsaPkcs sess objId (BSL.toStrict encKey) [Class SecretKey, KeyType AES]

        let aesKey = AESmod.initAES aesKeyBs
            encryptedMessage = AESmod.encryptECB aesKey "hello00000000000"

        -- test decryption using RSA key
        dec <- decrypt RsaPkcs sess objId (BSL.toStrict encKey)
        putStrLn $ show dec

        -- test decryption using AES key
        decAes <- decrypt AesEcb sess unwrappedKeyHandle encryptedMessage
        putStrLn $ show decAes
        logout sess

    releaseLibrary lib

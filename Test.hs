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


generateKey :: Library -> BU8.ByteString -> String -> IO (ObjectHandle, ObjectHandle)
generateKey lib pin label = do
    withSession lib 0 True $ \sess -> do
        login sess User pin
        generateKeyPair sess RsaPkcsKeyPairGen [ModulusBits 2048, Label label, Token True] [Label label, Token True]



main = do
    lib <- loadLibrary "/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib"
    info <- getInfo lib
    putStrLn(show info)
    slots <- getSlotList lib True 10
    putStrLn(show slots)

    putStrLn "getSlotInfo"
    slotInfo <- getSlotInfo lib 0
    putStrLn(show slotInfo)

    putStrLn "getTokenInfo"
    tokenInfo <- getTokenInfo lib 0
    putStrLn(show tokenInfo)

    putStrLn "getMechanismList"
    mechanisms <- getMechanismList lib 0 100
    putStrLn $ show mechanisms

    mechInfo <- getMechanismInfo lib 0 RsaPkcsKeyPairGen
    putStrLn $ show mechInfo

    --putStrLn "generating key"
    --(pubKeyHandle, privKeyHandle) <- generateKey lib (BU8.fromString "123abc_") "key"
    --putStrLn (show pubKeyHandle)

    withSession lib 0 False $ \sess -> do
        login sess User (BU8.fromString "123abc_")
        objects <- findObjects sess [Class PrivateKey, Label "key"]
        putStrLn $ show objects
        let objId = head objects
        mod <- getModulus sess objId
        pubExp <- getPublicExponent sess objId
        decryptFlag <- getDecryptFlag sess objId
        putStrLn $ show decryptFlag
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

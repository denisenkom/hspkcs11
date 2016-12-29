{-# LANGUAGE OverloadedStrings #-}
import qualified Data.ByteString.UTF8 as BU8
import Pkcs11
import Crypto.Random
import Crypto.Random.AESCtr
import qualified Codec.Crypto.RSA as RSA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL


generateKey :: Library -> BU8.ByteString -> String -> IO (ObjectHandle, ObjectHandle)
generateKey lib pin label = do
    withSession lib 0 rwSession $ \sess -> do
        login sess User pin
        generateKeyPair sess rsaPkcsKeyPairGen [ModulusBits 2048, Label label, Token True] [Label label, Token True]



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

    mechInfo <- getMechanismInfo lib 0 (fromIntegral $ head mechanisms)
    putStrLn $ show mechInfo

    withSession lib 0 0 $ \sess -> do
        login sess User (BU8.fromString "123abc_")
        objects <- findObjects sess [Class PrivateKey, Label "key"]
        putStrLn $ show objects
        let objId = head objects
        mod <- getModulus sess objId
        pubExp <- getPublicExponent sess objId
        attr <- getObjectAttr sess objId DecryptType
        putStrLn $ show attr
        rng <- newGenIO :: IO SystemRandom
        --let pubKey = RSA.PublicKey 256 mod pubExp
        --    (encText, rng') = RSA.encryptPKCS rng pubKey "hello"
        pubObjects <- findObjects sess [Class PublicKey, Label "key"]
        let pubKeyObjId = head pubObjects
        encText <- encrypt RsaPkcs sess pubKeyObjId "hello"
        putStrLn $ show encText
        let encTextLen = BS.length encText
        putStrLn $ show encTextLen

        dec <- decrypt RsaPkcs sess objId encText
        putStrLn $ show dec

    --putStrLn "generating key"
    --(pubKeyHandle, privKeyHandle) <- generateKey lib (BU8.fromString "123abc_") "key"
    --putStrLn (show pubKeyHandle)
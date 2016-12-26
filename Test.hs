import qualified Data.ByteString.UTF8 as BU8
import Pkcs11


generateKey :: Library -> BU8.ByteString -> String -> IO (ObjectHandle, ObjectHandle)
generateKey lib pin label = do
    withSession lib 0 rwSession $ \sess -> do
        login sess User pin
        generateKeyPair sess rsaPkcsKeyPairGen [ModulusBits 2048, Label label] [Label label, Token True]



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
        objects <- findObjects sess []
        putStrLn $ show objects

    --putStrLn "generating key"
    --(pubKeyHandle, privKeyHandle) <- generateKey lib (BU8.fromString "123abc_") "key"
    --putStrLn (show pubKeyHandle)

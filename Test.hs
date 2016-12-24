import Pkcs11


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

    withSession lib 0 serialSession $ \sess -> do
        objects <- findObjects sess [Class PrivateKey, KeyType RSA, ModulusBits 2048]
        putStrLn $ show objects
        (pubKeyHandle, privKeyHandle) <- generateKeyPair sess rsaPkcsKeyPairGen [ModulusBits 2048] []
        putStrLn $ show pubKeyHandle

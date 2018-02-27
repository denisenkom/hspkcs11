module System.Crypto.Pkcs11 (
    -- * Library
    Library,
    loadLibrary,
    releaseLibrary,

    -- ** Reading library information
    getInfo,
    LibraryInfo,
    infoCryptokiVersion,
    infoManufacturerId,
    infoFlags,
    infoLibraryDescription,
    infoLibraryVersion,
    Version,
    versionMajor,
    versionMinor,

    -- * Slots
    SlotId,
    getSlotNum,
    getSlotList,

    -- ** Reading slot information
    getSlotInfo,
    SlotInfo,
    slotInfoDescription,
    slotInfoManufacturerId,
    slotInfoFlags,
    slotInfoHardwareVersion,
    slotInfoFirmwareVersion,

    -- ** Working with tokens
    TokenInfo,
    getTokenInfo,
    tokenInfoLabel,
    tokenInfoManufacturerId,
    tokenInfoModel,
    tokenInfoSerialNumber,
    tokenInfoFlags,
    initToken,
    initPin,
    setPin,

    -- * Mechanisms
    getMechanismList,
    getMechanismInfo,
    MechType(..),
    MechInfo,
    mechInfoMinKeySize,
    mechInfoMaxKeySize,
    mechInfoFlags,
    Mech,
    simpleMech,

    -- * Session management
    Session,
    withSession,
    login,
    UserType(..),
    logout,
    closeAllSessions,
    getSessionInfo,
    SessionInfo,
    sessionInfoSlotId,
    sessionInfoState,
    sessionInfoFlags,
    sessionInfoDeviceError,
    SessionState(..),
    getOperationState,

    -- * Object attributes
    ObjectHandle,
    Attribute(..),
    ClassType(..),
    KeyTypeValue(..),
    destroyObject,
    createObject,
    copyObject,
    getObjectSize,
    -- ** Searching objects
    findObjects,
    -- ** Reading object attributes
    getTokenFlag,
    getPrivateFlag,
    getSensitiveFlag,
    getEncryptFlag,
    getDecryptFlag,
    getWrapFlag,
    getUnwrapFlag,
    getSignFlag,
    getModulus,
    getPublicExponent,
    getPrime,
    getBase,
    getEcdsaParams,
    getEcPoint,
    -- ** Writing attributes
    setAttributes,

    -- * Key generation
    generateKey,
    generateKeyPair,
    deriveKey,

    -- * Key wrapping/unwrapping
    wrapKey,
    unwrapKey,

    -- * Encryption/decryption
    decrypt,
    encrypt,
    -- ** Multipart operations
    decryptInit,
    encryptInit,
    encryptUpdate,
    encryptFinal,

    -- * Digest
    digest,
    digestInit,

    -- * Signing
    sign,
    verify,
    signRecover,
    signInit,
    verifyInit,
    signRecoverInit,

    -- * Random
    seedRandom,
    generateRandom,
) where
import Bindings.Pkcs11


-- | Represents a PKCS#11 library.
data Library = Library {
    libraryHandle :: DL,
    functionListPtr :: FunctionListPtr
}

-- | Return parameterless mechanism which can be used in cryptographic operation.
simpleMech :: MechType -> Mech
simpleMech mechType = Mech mechType nullPtr 0


getFunctionList :: GetFunctionListFunPtr -> IO ((Rv), (FunctionListPtr))
getFunctionList getFunctionListPtr =
  alloca $ \funcListPtrPtr -> do
    res <- (getFunctionList'_ getFunctionListPtr) funcListPtrPtr
    funcListPtr <- peek funcListPtrPtr
    return (fromIntegral res, funcListPtr)

-- | Return number of slots in the system.
getSlotNum :: Library -- ^ Library to be used for operation.
           -> Bool -- ^ If True will return only slots with tokens in them.
           -> IO (CULong) -- ^ Number of slots.
getSlotNum (Library _ functionListPtr) active = do
    (rv, outNum) <- getSlotList' functionListPtr active nullPtr 0
    if rv /= 0
        then fail $ "failed to get number of slots " ++ (rvToStr rv)
        else return outNum

-- | Get a list of slot IDs in the system.  Can filter for slots with attached tokens.
--
-- > slotsIds <- getSlotList lib True 10
--
-- In this example retrieves list of, at most 10 (third parameter) slot identifiers with tokens present (second parameter is set to True)
getSlotList :: Library -- ^ Library to be used for operation.
            -> Bool -- ^ If True will return only slots with tokens in them.
            -> Int -- ^ Maximum number of slot IDs to be returned.
            -> IO [SlotId]
getSlotList (Library _ functionListPtr) active num = do
    allocaArray num $ \array -> do
        (rv, outNum) <- getSlotList' functionListPtr active array (fromIntegral num)
        if rv /= 0
            then fail $ "failed to get list of slots " ++ (rvToStr rv)
            else peekArray (fromIntegral outNum) array


getSessionInfo (Session sessHandle funListPtr) = do
    (rv, sessInfo) <- getSessionInfo' funListPtr sessHandle
    if rv /= 0
        then fail $ "failed to get session info: " ++ (rvToStr rv)
        else return sessInfo


closeAllSessions (Library _ funcListPtr) slotId = do
    rv <- closeAllSessions' funcListPtr slotId
    if rv /= 0
        then fail $ "failed to close sessions: " ++ (rvToStr rv)
        else return ()

getOperationState (Session sessHandle funcListPtr) maxSize = do
    allocaBytes (fromIntegral maxSize) $ \bytesPtr -> do
        (rv, resSize) <- getOperationState' funcListPtr sessHandle bytesPtr maxSize
        if rv /= 0
            then fail $ "failed to get operation state: " ++ (rvToStr rv)
            else BS.packCStringLen (castPtr bytesPtr, fromIntegral resSize)

-- | Deletes an object from token or session.
destroyObject (Session sessHandle funcListPtr) objectHandle = do
    rv <- destroyObject' funcListPtr sessHandle objectHandle
    if rv /= 0
        then fail $ "failed to destroy object: " ++ (rvToStr rv)
        else return ()


-- | Generates a symmetric key using provided mechanism and applies provided attributes to resulting key object.
--
-- Examples:
--
-- Generate 128-bit AES key:
--
-- > keyHandle <- generateKey sess (simpleMech AesKeyGen) [ValueLen 16]
--
-- Generate 1024-bit Diffie-Hellman domain parameters using PKCS#3 mechanism:
--
-- > dhParamsHandle <- generateKey sess (simpleMech DhPkcsParameterGen) [PrimeBits 1028]
generateKey :: Session -> Mech -> [Attribute] -> IO ObjectHandle
generateKey (Session sessHandle funcListPtr) mech attribs = do
    (rv, keyHandle) <- generateKey' funcListPtr sessHandle mech attribs
    if rv /= 0
        then fail $ "failed to generate key: " ++ (rvToStr rv)
        else return keyHandle


-- | Represent session. Created by 'withSession' function.
data Session = Session SessionHandle FunctionListPtr


-- | Load PKCS#11 dynamically linked library from given path
--
-- > lib <- loadLibrary "/path/to/dll.so"
loadLibrary :: String -> IO Library
loadLibrary libraryPath = do
    lib <- dlopen libraryPath []
    getFunctionListFunPtr <- dlsym lib "C_GetFunctionList"
    (rv, functionListPtr) <- getFunctionList getFunctionListFunPtr
    if rv /= 0
        then fail $ "failed to get list of functions " ++ (rvToStr rv)
        else do
            rv <- initialize functionListPtr
            if rv /= 0
                then fail $ "failed to initialize library " ++ (rvToStr rv)
                else return Library { libraryHandle = lib, functionListPtr = functionListPtr }


-- | Releases resources used by loaded library
releaseLibrary lib = do
    rv <- finalize $ functionListPtr lib
    dlclose $ libraryHandle lib


-- | Get general information about Cryptoki library
getInfo :: Library -> IO LibraryInfo
getInfo (Library _ functionListPtr) = do
    (rv, info) <- getInfo' functionListPtr
    if rv /= 0
        then fail $ "failed to get library information " ++ (rvToStr rv)
        else return info


_openSessionEx :: Library -> SlotId -> Int -> IO Session
_openSessionEx (Library _ functionListPtr) slotId flags = do
    (rv, sessionHandle) <- openSession' functionListPtr slotId flags
    if rv /= 0
        then fail $ "failed to open slot: " ++ (rvToStr rv)
        else return $ Session sessionHandle functionListPtr


_closeSessionEx :: Session -> IO ()
_closeSessionEx (Session sessionHandle functionListPtr) = do
    rv <- closeSession' functionListPtr sessionHandle
    if rv /= 0
        then fail $ "failed to close slot: " ++ (rvToStr rv)
        else return ()


-- | Opens a read-only or read-write session with a token in a given slot and then closes it after callback function is finished.
withSession :: Library -- ^ Library to use.
            -> SlotId -- ^ Slot ID for which to open session.
            -> Bool -- ^ If True will open writable session, otherwise will open read-only session.
            -> (Session -> IO a) -- ^ Callback function which is executed while session is open.
            -> IO a -- ^ Returns a result of callback function.
withSession lib slotId writable f = do
    let flags = if writable then _rwSession else 0
    bracket
        (_openSessionEx lib slotId (flags .|. _serialSession))
        (_closeSessionEx)
        (f)



_findObjectsInitEx :: Session -> [Attribute] -> IO ()
_findObjectsInitEx (Session sessionHandle functionListPtr) attribs = do
    rv <- findObjectsInit' functionListPtr sessionHandle attribs
    if rv /= 0
        then fail $ "failed to initialize search: " ++ (rvToStr rv)
        else return ()


_findObjectsEx :: Session -> IO [ObjectHandle]
_findObjectsEx (Session sessionHandle functionListPtr) = do
    (rv, objectsHandles) <- findObjects' functionListPtr sessionHandle 10
    if rv /= 0
        then fail $ "failed to execute search: " ++ (rvToStr rv)
        else return objectsHandles


_findObjectsFinalEx :: Session -> IO ()
_findObjectsFinalEx (Session sessionHandle functionListPtr) = do
    rv <- findObjectsFinal' functionListPtr sessionHandle
    if rv /= 0
        then fail $ "failed to finalize search: " ++ (rvToStr rv)
        else return ()


-- | Searches current session for objects matching provided attributes list, returns a list of matching object handles
findObjects :: Session -> [Attribute] -> IO [ObjectHandle]
findObjects session attribs = do
    _findObjectsInitEx session attribs
    finally (_findObjectsEx session) (_findObjectsFinalEx session)


-- | Generates an asymmetric key pair using provided mechanism.
--
-- Examples:
--
-- Generate an 2048-bit RSA key:
--
-- > (pubKey, privKey) <- generateKeyPair sess (simpleMech RsaPkcsKeyPairGen) [ModulusBits 2048] []
generateKeyPair :: Session -- ^ session in which to generate key
                -> Mech -- ^ a mechanism to use for key generation, for example 'simpleMech RsaPkcs'
                -> [Attribute] -- ^ attributes applied to generated public key object
                -> [Attribute] -- ^ attributes applied to generated private key object
                -> IO (ObjectHandle, ObjectHandle) -- ^ created objects references, first is public key, second is private key
generateKeyPair (Session sessionHandle functionListPtr) mech pubKeyAttrs privKeyAttrs = do
    (rv, pubKeyHandle, privKeyHandle) <- _generateKeyPair functionListPtr sessionHandle mech pubKeyAttrs privKeyAttrs
    if rv /= 0
        then fail $ "failed to generate key pair: " ++ (rvToStr rv)
        else return (pubKeyHandle, privKeyHandle)
-- | Initialize a token in a given slot.  All objects created by user on the token are destroyed.
initToken :: Library -- ^ PKCS#11 library
          -> SlotId  -- ^ slot id in which to initialize token
          -> BU8.ByteString -- ^ token's security officer password
          -> String  -- ^ new label for the token
          -> IO ()
initToken (Library _ funcListPtr) slotId pin label = do
    rv <- initToken' funcListPtr slotId pin label
    if rv /= 0
        then fail $ "failed to initialize token " ++ (rvToStr rv)
        else return ()


-- | Obtains information about a particular slot in the system
--
-- > slotInfo <- getSlotInfo lib slotId
getSlotInfo :: Library -> SlotId -> IO SlotInfo
getSlotInfo (Library _ functionListPtr) slotId = do
    (rv, slotInfo) <- getSlotInfo' functionListPtr slotId
    if rv /= 0
        then fail $ "failed to get slot information " ++ (rvToStr rv)
        else return slotInfo


-- | Obtains information about a particular token in the system
--
-- > tokenInfo <- getTokenInfo lib slotId
getTokenInfo :: Library -> SlotId -> IO TokenInfo
getTokenInfo (Library _ functionListPtr) slotId = do
    (rv, slotInfo) <- getTokenInfo' functionListPtr slotId
    if rv /= 0
        then fail $ "failed to get token information " ++ (rvToStr rv)
        else return slotInfo

-- | Derives a key from a base key using provided mechanism and applies provided attributes to a resulting key.
-- Can be used to derive symmetric key using Diffie-Hellman key exchange.
deriveKey (Session sessHandle funcListPtr) mech baseKeyHandle attribs = do
    _withAttribs attribs $ \attribsPtr -> do
        (rv, createdHandle) <- deriveKey' funcListPtr sessHandle mech baseKeyHandle attribsPtr (fromIntegral $ length attribs)
        if rv /= 0
            then fail $ "failed to derive key: " ++ (rvToStr rv)
            else return createdHandle

-- | Creates an object from given list of attributes and returns a reference to created object.
createObject (Session sessHandle funcListPtr) attribs = do
    _withAttribs attribs $ \attribsPtr -> do
        (rv, createdHandle) <- createObject' funcListPtr sessHandle attribsPtr (fromIntegral $ length attribs)
        if rv /= 0
            then fail $ "failed to create object: " ++ (rvToStr rv)
            else return createdHandle

-- | Makes a copy of an object and changes attributes of copied object, returns a reference to new object.
copyObject (Session sessHandle funcListPtr) objHandle attribs = do
    _withAttribs attribs $ \attribsPtr -> do
        (rv, createdHandle) <- copyObject' funcListPtr sessHandle objHandle attribsPtr (fromIntegral $ length attribs)
        if rv /= 0
            then fail $ "failed to copy object: " ++ (rvToStr rv)
            else return createdHandle

-- | Returns an approximate amount of space occupied by an object in bytes.
getObjectSize (Session sessHandle funcListPtr) objHandle = do
    (rv, objSize) <- getObjectSize' funcListPtr sessHandle objHandle
    if rv /= 0
        then fail $ "failed to get object size: " ++ (rvToStr rv)
        else return objSize


getBoolAttr :: Session -> ObjectHandle -> AttributeType -> IO Bool
getBoolAttr (Session sessHandle funcListPtr) objHandle attrType = do
    alloca $ \valuePtr -> do
        _getAttr funcListPtr sessHandle objHandle attrType (valuePtr :: Ptr CK_BBOOL)
        val <- peek valuePtr
        return $ toBool val


getTokenFlag sess objHandle = getBoolAttr sess objHandle TokenType
getPrivateFlag sess objHandle = getBoolAttr sess objHandle PrivateType
getSensitiveFlag sess objHandle = getBoolAttr sess objHandle SensitiveType
getEncryptFlag sess objHandle = getBoolAttr sess objHandle EncryptType
getDecryptFlag sess objHandle = getBoolAttr sess objHandle DecryptType
getWrapFlag sess objHandle = getBoolAttr sess objHandle WrapType
getUnwrapFlag sess objHandle = getBoolAttr sess objHandle UnwrapType
getSignFlag sess objHandle = getBoolAttr sess objHandle SignType

getModulus :: Session -> ObjectHandle -> IO Integer
getModulus sess objHandle = do
    (Modulus m) <- getObjectAttr sess objHandle ModulusType
    return m

getPublicExponent :: Session -> ObjectHandle -> IO Integer
getPublicExponent sess objHandle = do
    (PublicExponent v) <- getObjectAttr sess objHandle PublicExponentType
    return v

getPrime sess objHandle = do
    (Prime p) <- getObjectAttr sess objHandle PrimeType
    return p

getBase sess objHandle = do
    (Base p) <- getObjectAttr sess objHandle BaseType
    return p

getEcdsaParams sess objHandle = do
    (EcdsaParams bs) <- getObjectAttr sess objHandle EcParamsType
    return bs

getEcPoint sess objHandle = do
    (EcPoint bs) <- getObjectAttr sess objHandle EcPointType
    return bs

-- | Modifies attributes of an object.
setAttributes (Session sessHandle funcListPtr) objHandle attribs = do
    _withAttribs attribs $ \attribsPtr -> do
        rv <- setAttributeValue' funcListPtr sessHandle objHandle attribsPtr (fromIntegral $ length attribs)
        if rv /= 0
            then fail $ "failed to set attributes: " ++ (rvToStr rv)
            else return ()


-- | Initializes normal user's PIN.  Session should be logged in by SO user in other words it should be in
-- 'RWSOFunctions' state.
initPin :: Session -> BU8.ByteString -> IO ()
initPin (Session sessHandle funcListPtr) pin = do
    rv <- initPin' funcListPtr sessHandle pin
    if rv /= 0
        then fail $ "initPin failed: " ++ (rvToStr rv)
        else return ()


-- | Changes PIN of a currently logged in user.
setPin :: Session  -- ^ session to act on
       -> BU8.ByteString -- ^ old PIN
       -> BU8.ByteString -- ^ new PIN
       -> IO ()
setPin (Session sessHandle funcListPtr) oldPin newPin = do
    rv <- setPin' funcListPtr sessHandle oldPin newPin
    if rv /= 0
        then fail $ "setPin failed: " ++ (rvToStr rv)
        else return ()


-- | Logs a user into a token.
login :: Session -- ^ session to act on
      -> UserType -- ^ type of user to login
      -> BU8.ByteString -- ^ user's PIN
      -> IO ()
login (Session sessionHandle functionListPtr) userType pin = do
    rv <- _login functionListPtr sessionHandle userType pin
    if rv /= 0
        then fail $ "login failed: " ++ (rvToStr rv)
        else return ()


-- | Logs a user out from a token.
logout :: Session -> IO ()
logout (Session sessionHandle functionListPtr) = do
    rv <- {#call unsafe CK_FUNCTION_LIST.C_Logout#} functionListPtr sessionHandle
    if rv /= 0
        then fail $ "logout failed: " ++ (rvToStr rv)
        else return ()


-- | Initialize a multi-part decryption operation using provided mechanism and key.
decryptInit :: Mech -> Session -> ObjectHandle -> IO ()
decryptInit mech (Session sessionHandle functionListPtr) obj = do
    rv <- decryptInit' functionListPtr sessionHandle mech obj
    if rv /= 0
        then fail $ "failed to initiate decryption: " ++ (rvToStr rv)
        else return ()


-- | Decrypt data using provided mechanism and key handle.
--
-- Example AES ECB decryption.
--
-- > decData <- decrypt (simpleMech AesEcb) sess aesKeyHandle encData 1000
decrypt :: Mech -- ^ Mechanism used for decryption.
        -> Session -- ^ Session on which key resides.
        -> ObjectHandle -- ^ Key handle used for decryption.
        -> BS.ByteString -- ^ Encrypted data to be decrypted.
        -> CULong -- ^ Maximum number of bytes to be returned.
        -> IO BS.ByteString -- ^ Decrypted data
decrypt mech (Session sessionHandle functionListPtr) keyHandle encData outLen = do
    decryptInit mech (Session sessionHandle functionListPtr) keyHandle
    unsafeUseAsCStringLen encData $ \(encDataPtr, encDataLen) -> do
        allocaBytes (fromIntegral outLen) $ \outDataPtr -> do
            (rv, outDataLen) <- decrypt' functionListPtr sessionHandle (castPtr encDataPtr) (fromIntegral encDataLen) outLen outDataLenPtr
            if rv /= 0
                then fail $ "failed to decrypt: " ++ (rvToStr rv)
                else BS.packCStringLen (castPtr outDataPtr, fromIntegral outDataLen)

-- | Initialize multi-part encryption operation.
encryptInit :: Mech -- ^ Mechanism to use for encryption.
               -> Session -- ^ Session in which to perform operation.
               -> ObjectHandle -- ^ Key handle.
               -> IO ()
encryptInit mech (Session sessionHandle functionListPtr) obj = do
    rv <- encryptInit' functionListPtr sessionHandle mech obj
    if rv /= 0
        then fail $ "failed to initiate decryption: " ++ (rvToStr rv)
        else return ()

-- | Encrypt data using provided mechanism and key handle.
encrypt :: Mech -- ^ Mechanism to use for encryption.
        -> Session -- ^ Session in which to perform operation.
        -> ObjectHandle -- ^ Key handle.
        -> BS.ByteString -- ^ Data to be encrypted.
        -> CULong -- ^ Maximum number of bytes to be returned.
        -> IO BS.ByteString -- ^ Encrypted data.
encrypt mech (Session sessionHandle functionListPtr) keyHandle encData outLen = do
    encryptInit mech (Session sessionHandle functionListPtr) keyHandle
    allocaBytes (fromIntegral outLen) $ \outDataPtr -> do
        (rv, outDataLen) <- encrypt' functionListPtr sessionHandle (castPtr encDataPtr) (fromIntegral encDataLen) outDataPtr outLen
        if rv /= 0
            then fail $ "failed to decrypt: " ++ (rvToStr rv)
            else BS.packCStringLen (castPtr outDataPtr, fromIntegral outDataLen)


encryptUpdate (Session sessHandle funcListPtr) inData outLen = do
    allocaBytes (fromIntegral outLen) $ \outPtr -> do
        (rv, outResLen) <- encryptUpdate' funcListPtr sessHandle inData (fromIntegral $ BS.length inData) outPtr outLen
        if rv /= 0
            then fail $ "failed to encrypt part: " ++ (rvToStr rv)
            else BS.packCStringLen (castPtr outPtr, fromIntegral outResLen)

encryptFinal (Session sessHandle funcListPtr) outLen = do
    allocaBytes (fromIntegral outLen) $ \outPtr -> do
        (rv, outResLen) <- encryptFinal' funcListPtr sessHandle outPtr outLen
        if rv /= 0
            then fail $ "failed to complete encryption: " ++ (rvToStr rv)
            else BS.packCStringLen (castPtr outPtr, fromIntegral outResLen)

digestInit :: Mech -> Session -> IO ()
digestInit mech (Session sessHandle funcListPtr) = do
    rv <- digestInit' funcListPtr sessHandle mech
    if rv /= 0
        then fail $ "failed to initialize digest operation: " ++ (rvToStr rv)
        else return ()

-- | Calculates digest aka hash of a data using provided mechanism.
--
-- Example calculating SHA256 hash:
--
-- >>> digest (simpleMech Sha256) sess (replicate 16 0) 1000
-- "7G\b\255\247q\157\213\151\158\200u\213l\210(om<\247\236\&1z;%c*\171(\236\&7\187"
digest :: Mech -- ^ Digest mechanism.
       -> Session -- ^ Session to be used for digesting.
       -> BS.ByteString -- ^ Data to be digested.
       -> CULong -- ^ Maximum number of bytes to be returned.
       -> IO (BS.ByteString) -- ^ Resulting digest.
digest mech (Session sessHandle funcListPtr) digestData outLen = do
    digestInit mech (Session sessHandle funcListPtr)
    allocaBytes (fromIntegral outLen) $ \outPtr -> do
        (rv, outResLen) <- digest' funcListPtr sessHandle digestData (fromIntegral $ BS.length digestData) outPtr outLen
        if rv /= 0
            then fail $ "failed to digest: " ++ (rvToStr rv)
            else BS.packCStringLen (castPtr outPtr, fromIntegral outResLen)


signInit :: Mech -> Session -> ObjectHandle -> IO ()
signInit mech (Session sessHandle funcListPtr) objHandle = do
    rv <- signInit' funcListPtr sessHandle mech objHandle
    if rv /= 0
        then fail $ "failed to initialize signing operation: " ++ (rvToStr rv)
        else return ()

-- | Signs data using provided mechanism and key.
--
-- Example signing with RSA PKCS#1
--
-- > signature <- sign (simpleMech RsaPkcs) sess privKeyHandle signedData 1000
sign :: Mech -- ^ Mechanism to use for signing.
     -> Session -- ^ Session to work in.
     -> ObjectHandle -- ^ Key handle.
     -> BS.ByteString -- ^ Data to be signed.
     -> CULong -- ^ Maximum number of bytes to be returned.
     -> IO (BS.ByteString) -- ^ Signature.
sign mech (Session sessHandle funcListPtr) key signData outLen = do
    signInit mech (Session sessHandle funcListPtr) key
    with outLen $ \outLenPtr -> do
        allocaBytes (fromIntegral outLen) $ \outPtr -> do
            (rv, outResLen) <- sign' funcListPtr sessHandle signData (fromIntegral $ BS.length signData) outPtr outLen
            if rv /= 0
                then fail $ "failed to sign: " ++ (rvToStr rv)
                else BS.packCStringLen (castPtr outPtr, fromIntegral outResLen)

signRecoverInit :: Mech -> Session -> ObjectHandle -> IO ()
signRecoverInit mech (Session sessHandle funcListPtr) objHandle = do
    rv <- signRecoverInit' funcListPtr sessHandle mech objHandle
    if rv /= 0
        then fail $ "failed to initialize signing with recovery operation: " ++ (rvToStr rv)
        else return ()

signRecover (Session sessHandle funcListPtr) signData outLen = do
    with outLen $ \outLenPtr -> do
        allocaBytes (fromIntegral outLen) $ \outPtr -> do
            (rv, outResLen) <- signRecover' funcListPtr sessHandle signData (fromIntegral $ BS.length signData) outPtr outLen
            if rv /= 0
                then fail $ "failed to sign with recovery: " ++ (rvToStr rv)
                else BS.packCStringLen (castPtr outPtr, fromIntegral outResLen)

verifyInit :: Session -> Mech -> ObjectHandle -> IO ()
verifyInit (Session sessHandle funcListPtr) mech objHandle = do
    rv <- verifyInit' funcListPtr sessHandle mech objHandle
    if rv /= 0
        then fail $ "failed to initialize verify operation: " ++ (rvToStr rv)
        else return ()

-- | Verifies signature using provided mechanism and key.
--
-- Example signature verification using RSA public key:
--
-- >>> verify (simpleMech RsaPkcs) sess pubKeyHandle signedData signature
-- True
verify :: Mech -- ^ Mechanism to be used for signature validation.
       -> Session -- ^ Session to be used.
       -> ObjectHandle -- ^ Key handle.
       -> BS.ByteString -- ^ Signed data.
       -> BS.ByteString -- ^ Signature.
       -> IO (Bool) -- ^ True is signature is valid, False otherwise.
verify mech (Session sessHandle funcListPtr) keyHandle signData signatureData = do
    verifyInit (Session sessHandle funcListPtr) mech keyHandle
    rv <- verify' funcListPtr sessHandle signData (fromIntegral $ BS.length signData) signatureData (fromIntegral $ BS.length signatureData)
    case rv of 0 -> return True
               {#const CKR_SIGNATURE_INVALID#} -> return False
               _ -> fail $ "failed to verify: " ++ (rvToStr rv)

-- | Wrap a key using provided wrapping key and return opaque byte array representing wrapped key.  This byte array
-- can be stored in user application and can be used later to recreate wrapped key using 'unwrapKey' function.
--
-- Example wrapping AES key using RSA public key:
--
-- > wrappedAesKey <- wrapKey (simpleMech RsaPkcs) sess pubRsaKeyHandle aesKeyHandle 300
wrapKey :: Mech -- ^ Mechanism used to wrap key (to encrypt)
        -> Session -- ^ Session in which both keys reside.
        -> ObjectHandle -- ^ Key which will be used to wrap (encrypt) another key
        -> ObjectHandle -- ^ Key to be wrapped
        -> CULong -- ^ Maximum size in bytes of a resulting byte array
        -> IO BS.ByteString -- ^ Resulting opaque wrapped key
wrapKey mech (Session sessHandle funcListPtr) wrappingKey key dataLen = do
    allocaBytes (fromIntegral dataLen) $ \dataPtr -> do
        (rv, outDataLen) <- wrapKey' funcListPtr sessHandle mech wrappingKey key dataPtr dataLen
        if rv /= 0
            then fail $ "failed to wrap key: " ++ (rvToStr rv)
            else BS.packCStringLen (castPtr dataPtr, fromIntegral outDataLen)


-- | Unwrap a key from opaque byte string and apply attributes to a resulting key object.
--
-- Example unwrapping AES key using RSA private key:
--
-- > unwrappedAesKey <- unwrapKey (simpleMech RsaPkcs) sess privRsaKeyHandle wrappedAesKey [Class SecretKey, KeyType AES]
unwrapKey :: Mech -- ^ Mechanism to use for unwrapping (decryption).
          -> Session -- ^ Session in which to perform operation.
          -> ObjectHandle -- ^ Handle to a key which will be used to unwrap (decrypt) key.
          -> BS.ByteString -- ^ Key to be unwrapped.
          -> [Attribute] -- ^ Attributes applied to unwrapped key object.
          -> IO ObjectHandle -- ^ Unwrapped key handle.
unwrapKey mech (Session sessionHandle functionListPtr) key wrappedKey template = do
    _withAttribs template $ \attribsPtr -> do
        with mech $ \mechPtr -> do
            unsafeUseAsCStringLen wrappedKey $ \(wrappedKeyPtr, wrappedKeyLen) -> do
                alloca $ \unwrappedKeyPtr -> do
                    rv <- {#call unsafe CK_FUNCTION_LIST.C_UnwrapKey#} functionListPtr sessionHandle mechPtr key (castPtr wrappedKeyPtr) (fromIntegral wrappedKeyLen) attribsPtr (fromIntegral $ length template) unwrappedKeyPtr
                    if rv /= 0
                        then fail $ "failed to unwrap key: " ++ (rvToStr rv)
                        else do
                            unwrappedKey <- peek unwrappedKeyPtr
                            return unwrappedKey

-- | Mixes provided seed data with token's seed
seedRandom (Session sessHandle funcListPtr) seedData = do
    rv <- seedRandom' funcListPtr sessHandle seedData (fromIntegral $ BS.length seedData)
    if rv /= 0
        then fail $ "failed to seed random: " ++ (rvToStr rv)
        else return ()

-- | Generates random data using token's RNG.
generateRandom :: Session -- ^ Session to work on.
               -> CULong -- ^ Number of bytes to generate.
               -> IO BS.ByteString -- ^ Generated random bytes.
generateRandom (Session sessHandle funcListPtr) randLen = do
    allocaBytes (fromIntegral randLen) $ \randPtr -> do
        rv <- generateRandom' funcListPtr sessHandle randPtr randLen
        if rv /= 0
            then fail $ "failed to generate random data: " ++ (rvToStr rv)
            else BS.packCStringLen (castPtr randPtr, fromIntegral randLen)


-- | Obtains a list of mechanism types supported by a token
getMechanismList :: Library -> SlotId -> Int -> IO [Int]
getMechanismList (Library _ functionListPtr) slotId maxMechanisms = do
    (rv, types) <- _getMechanismList functionListPtr slotId maxMechanisms
    if rv /= 0
        then fail $ "failed to get list of mechanisms: " ++ (rvToStr rv)
        else return $ map (fromIntegral) types


-- | Obtains information about a particular mechanism possibly supported by a token
getMechanismInfo :: Library -> SlotId -> MechType -> IO MechInfo
getMechanismInfo (Library _ functionListPtr) slotId mechId = do
    (rv, types) <- _getMechanismInfo functionListPtr slotId (fromEnum mechId)
    if rv /= 0
        then fail $ "failed to get mechanism information: " ++ (rvToStr rv)
        else return types

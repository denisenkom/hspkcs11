{-# LANGUAGE ForeignFunctionInterface #-}
module Pkcs11 where
import Foreign
import Foreign.Marshal.Utils
import Foreign.Marshal.Alloc
import Foreign.C
import Foreign.Ptr
import System.Posix.DynamicLinker
import Control.Monad
import Control.Exception
import qualified Data.ByteString.UTF8 as BU8
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe

#include "pkcs11import.h"

{-
 Currently cannot use c2hs structure alignment and offset detector since it does not support pragma pack
 which is required by PKCS11, which is using 1 byte packing
 https://github.com/haskell/c2hs/issues/172
-}

_serialSession = {#const CKF_SERIAL_SESSION#} :: Int
rwSession = {#const CKF_RW_SESSION#} :: Int

rsaPkcsKeyPairGen = {#const CKM_RSA_PKCS_KEY_PAIR_GEN#} :: Int

type ObjectHandle = {#type CK_OBJECT_HANDLE#}
type SlotId = {#type CK_SLOT_ID#}
type Rv = {#type CK_RV#}
type CK_BYTE = {#type CK_BYTE#}
type CK_FLAGS = {#type CK_FLAGS#}
type GetFunctionListFunPtr = {#type CK_C_GetFunctionList#}
type GetSlotListFunPtr = {#type CK_C_GetSlotList#}
type NotifyFunPtr = {#type CK_NOTIFY#}
type SessionHandle = {#type CK_SESSION_HANDLE#}

{#pointer *CK_FUNCTION_LIST as FunctionListPtr#}
{#pointer *CK_INFO as InfoPtr -> Info#}
{#pointer *CK_SLOT_INFO as SlotInfoPtr -> SlotInfo#}
{#pointer *CK_TOKEN_INFO as TokenInfoPtr -> TokenInfo#}
{#pointer *CK_ATTRIBUTE as LlAttributePtr -> LlAttribute#}
{#pointer *CK_MECHANISM_INFO as MechInfoPtr -> MechInfo#}
{#pointer *CK_MECHANISM as MechPtr -> Mech#}

-- defined this one manually because I don't know how to make c2hs to define it yet
type GetFunctionListFun = (C2HSImp.Ptr (FunctionListPtr)) -> (IO C2HSImp.CULong)

foreign import ccall unsafe "dynamic"
  getFunctionList'_ :: GetFunctionListFunPtr -> GetFunctionListFun

data Version = Version {
    versionMajor :: Int,
    versionMinor :: Int
} deriving (Show)

instance Storable Version where
  sizeOf _ = {#sizeof CK_VERSION#}
  alignment _ = {#alignof CK_VERSION#}
  peek p = Version
    <$> liftM fromIntegral ({#get CK_VERSION->major#} p)
    <*> liftM fromIntegral ({#get CK_VERSION->minor#} p)
  poke p x = do
    {#set CK_VERSION->major#} p (fromIntegral $ versionMajor x)
    {#set CK_VERSION->minor#} p (fromIntegral $ versionMinor x)

data Info = Info {
    infoCryptokiVersion :: Version,
    infoManufacturerId :: String,
    infoFlags :: CK_FLAGS,
    infoLibraryDescription :: String,
    infoLibraryVersion :: Version
} deriving (Show)

instance Storable Info where
  sizeOf _ = (2+32+4+32+10+2)
  alignment _ = 1
  peek p = do
    ver <- peek (p `plusPtr` {#offsetof CK_INFO->cryptokiVersion#}) :: IO Version
    manufacturerId <- peekCStringLen ((p `plusPtr` 2), 32)
    flags <- (\ptr -> do {C2HSImp.peekByteOff ptr (2+32) :: IO C2HSImp.CULong}) p
    --flags <- {#get CK_INFO->flags#} p
    libraryDescription <- peekCStringLen ((p `plusPtr` (2+32+4+10)), 32)
    --libraryDescription <- {# get CK_INFO->libraryDescription #} p
    libVer <- peek (p `plusPtr` (2+32+4+32+10)) :: IO Version
    return Info {infoCryptokiVersion=ver,
                 infoManufacturerId=manufacturerId,
                 infoFlags=fromIntegral flags,
                 infoLibraryDescription=libraryDescription,
                 infoLibraryVersion=libVer
                 }


peekInfo :: Ptr Info -> IO Info
peekInfo ptr = peek ptr


data SlotInfo = SlotInfo {
    slotInfoDescription :: String,
    slotInfoManufacturerId :: String,
    slotInfoFlags :: Int,
    slotInfoHardwareVersion :: Version,
    slotInfoFirmwareVersion :: Version
} deriving (Show)

instance Storable SlotInfo where
  sizeOf _ = (64+32+4+2+2)
  alignment _ = 1
  peek p = do
    description <- peekCStringLen ((p `plusPtr` 0), 64)
    manufacturerId <- peekCStringLen ((p `plusPtr` 64), 32)
    flags <- C2HSImp.peekByteOff p (64+32) :: IO C2HSImp.CULong
    hwVer <- peek (p `plusPtr` (64+32+4)) :: IO Version
    fwVer <- peek (p `plusPtr` (64+32+4+2)) :: IO Version
    return SlotInfo {slotInfoDescription=description,
                     slotInfoManufacturerId=manufacturerId,
                     slotInfoFlags=fromIntegral flags,
                     slotInfoHardwareVersion=hwVer,
                     slotInfoFirmwareVersion=fwVer
                     }


data TokenInfo = TokenInfo {
    tokenInfoLabel :: String,
    tokenInfoManufacturerId :: String,
    tokenInfoModel :: String,
    tokenInfoSerialNumber :: String,
    tokenInfoFlags :: Int--,
    --tokenInfoHardwareVersion :: Version,
    --tokenInfoFirmwareVersion :: Version
} deriving (Show)

instance Storable TokenInfo where
    sizeOf _ = (64+32+4+2+2)
    alignment _ = 1
    peek p = do
        label <- peekCStringLen ((p `plusPtr` 0), 32)
        manufacturerId <- peekCStringLen ((p `plusPtr` 32), 32)
        model <- peekCStringLen ((p `plusPtr` (32+32)), 16)
        serialNumber <- peekCStringLen ((p `plusPtr` (32+32+16)), 16)
        flags <- C2HSImp.peekByteOff p (32+32+16+16) :: IO C2HSImp.CULong
        --hwVer <- peek (p `plusPtr` (64+32+4)) :: IO Version
        --fwVer <- peek (p `plusPtr` (64+32+4+2)) :: IO Version
        return TokenInfo {tokenInfoLabel=label,
                          tokenInfoManufacturerId=manufacturerId,
                          tokenInfoModel=model,
                          tokenInfoSerialNumber=serialNumber,
                          tokenInfoFlags=fromIntegral flags--,
                          --tokenInfoHardwareVersion=hwVer,
                          --tokenInfoFirmwareVersion=fwVer
                          }


data MechInfo = MechInfo {
    mechInfoMinKeySize :: Int,
    mechInfoMaxKeySize :: Int,
    mechInfoFlags :: Int
} deriving (Show)

instance Storable MechInfo where
  sizeOf _ = {#sizeof CK_MECHANISM_INFO#}
  alignment _ = 1
  peek p = MechInfo
    <$> liftM fromIntegral ({#get CK_MECHANISM_INFO->ulMinKeySize#} p)
    <*> liftM fromIntegral ({#get CK_MECHANISM_INFO->ulMaxKeySize#} p)
    <*> liftM fromIntegral ({#get CK_MECHANISM_INFO->flags#} p)
  poke p x = do
    {#set CK_MECHANISM_INFO->ulMinKeySize#} p (fromIntegral $ mechInfoMinKeySize x)
    {#set CK_MECHANISM_INFO->ulMaxKeySize#} p (fromIntegral $ mechInfoMaxKeySize x)
    {#set CK_MECHANISM_INFO->flags#} p (fromIntegral $ mechInfoFlags x)


data Mech = Mech {
    mechType :: Int,
    mechParamPtr :: Ptr (),
    mechParamSize :: Int
}

instance Storable Mech where
    sizeOf _ = {#sizeof CK_MECHANISM_TYPE#} + {#sizeof CK_VOID_PTR#} + {#sizeof CK_ULONG#}
    alignment _ = 1
    poke p x = do
        poke (p `plusPtr` 0) (mechType x)
        poke (p `plusPtr` {#sizeof CK_MECHANISM_TYPE#}) (mechParamPtr x :: {#type CK_VOID_PTR#})
        poke (p `plusPtr` ({#sizeof CK_MECHANISM_TYPE#} + {#sizeof CK_VOID_PTR#})) (mechParamSize x)



{#fun unsafe CK_FUNCTION_LIST.C_Initialize as initialize
 {`FunctionListPtr',
  alloca- `()' } -> `Rv' fromIntegral#}

{#fun unsafe CK_FUNCTION_LIST.C_GetInfo as getInfo'
 {`FunctionListPtr',
  alloca- `Info' peekInfo* } -> `Rv' fromIntegral#}


getSlotList' functionListPtr active num = do
  alloca $ \arrayLenPtr -> do
    poke arrayLenPtr (fromIntegral num)
    allocaArray num $ \array -> do
      res <- {#call unsafe CK_FUNCTION_LIST.C_GetSlotList#} functionListPtr (fromBool active) array arrayLenPtr
      arrayLen <- peek arrayLenPtr
      slots <- peekArray (fromIntegral arrayLen) array
      return (fromIntegral res, slots)


{#fun unsafe CK_FUNCTION_LIST.C_GetSlotInfo as getSlotInfo'
  {`FunctionListPtr',
   `Int',
   alloca- `SlotInfo' peek* } -> `Rv' fromIntegral
#}


{#fun unsafe CK_FUNCTION_LIST.C_GetTokenInfo as getTokenInfo'
  {`FunctionListPtr',
   `Int',
   alloca- `TokenInfo' peek* } -> `Rv' fromIntegral
#}


openSession' functionListPtr slotId flags =
  alloca $ \slotIdPtr -> do
    res <- {#call unsafe CK_FUNCTION_LIST.C_OpenSession#} functionListPtr (fromIntegral slotId) (fromIntegral flags) nullPtr nullFunPtr slotIdPtr
    slotId <- peek slotIdPtr
    return (fromIntegral res, fromIntegral slotId)


{#fun unsafe CK_FUNCTION_LIST.C_CloseSession as closeSession'
 {`FunctionListPtr',
  `CULong' } -> `Rv' fromIntegral#}


{#fun unsafe CK_FUNCTION_LIST.C_Finalize as finalize
 {`FunctionListPtr',
  alloca- `()' } -> `Rv' fromIntegral#}


getFunctionList :: GetFunctionListFunPtr -> IO ((Rv), (FunctionListPtr))
getFunctionList getFunctionListPtr =
  alloca $ \funcListPtrPtr -> do
    res <- (getFunctionList'_ getFunctionListPtr) funcListPtrPtr
    funcListPtr <- peek funcListPtrPtr
    return (fromIntegral res, funcListPtr)


findObjectsInit' functionListPtr session attribs = do
    _withAttribs attribs $ \attribsPtr -> do
        res <- {#call unsafe CK_FUNCTION_LIST.C_FindObjectsInit#} functionListPtr session attribsPtr (fromIntegral $ length attribs)
        return (fromIntegral res)


findObjects' functionListPtr session maxObjects = do
  alloca $ \arrayLenPtr -> do
    poke arrayLenPtr (fromIntegral 0)
    allocaArray maxObjects $ \array -> do
      res <- {#call unsafe CK_FUNCTION_LIST.C_FindObjects#} functionListPtr session array (fromIntegral maxObjects) arrayLenPtr
      arrayLen <- peek arrayLenPtr
      objectHandles <- peekArray (fromIntegral arrayLen) array
      return (fromIntegral res, objectHandles)


{#fun unsafe CK_FUNCTION_LIST.C_FindObjectsFinal as findObjectsFinal'
 {`FunctionListPtr',
  `CULong' } -> `Rv' fromIntegral#}


{#enum define UserType {CKU_USER as User, CKU_SO as SecurityOfficer, CKU_CONTEXT_SPECIFIC as ContextSpecific} deriving (Eq) #}


_login :: FunctionListPtr -> SessionHandle -> UserType -> BU8.ByteString -> IO (Rv)
_login functionListPtr session userType pin = do
    unsafeUseAsCStringLen pin $ \(pinPtr, pinLen) -> do
        res <- {#call unsafe CK_FUNCTION_LIST.C_Login#} functionListPtr session (fromIntegral $ fromEnum userType) (castPtr pinPtr) (fromIntegral pinLen)
        return (fromIntegral res)


_generateKeyPair :: FunctionListPtr -> SessionHandle -> Int -> [Attribute] -> [Attribute] -> IO (Rv, ObjectHandle, ObjectHandle)
_generateKeyPair functionListPtr session mechType pubAttrs privAttrs = do
    alloca $ \pubKeyHandlePtr -> do
        alloca $ \privKeyHandlePtr -> do
            alloca $ \mechPtr -> do
                poke mechPtr (Mech {mechType = mechType, mechParamPtr = nullPtr, mechParamSize = 0})
                _withAttribs pubAttrs $ \pubAttrsPtr -> do
                    _withAttribs privAttrs $ \privAttrsPtr -> do
                        res <- {#call unsafe CK_FUNCTION_LIST.C_GenerateKeyPair#} functionListPtr session mechPtr pubAttrsPtr (fromIntegral $ length pubAttrs) privAttrsPtr (fromIntegral $ length privAttrs) pubKeyHandlePtr privKeyHandlePtr
                        pubKeyHandle <- peek pubKeyHandlePtr
                        privKeyHandle <- peek privKeyHandlePtr
                        return (fromIntegral res, fromIntegral pubKeyHandle, fromIntegral privKeyHandle)



_getMechanismList :: FunctionListPtr -> Int -> Int -> IO (Rv, [CULong])
_getMechanismList functionListPtr slotId maxMechanisms = do
    alloca $ \arrayLenPtr -> do
        poke arrayLenPtr (fromIntegral maxMechanisms)
        allocaArray maxMechanisms $ \array -> do
            res <- {#call unsafe CK_FUNCTION_LIST.C_GetMechanismList#} functionListPtr (fromIntegral slotId) array arrayLenPtr
            arrayLen <- peek arrayLenPtr
            objectHandles <- peekArray (fromIntegral arrayLen) array
            return (fromIntegral res, objectHandles)


{#fun unsafe CK_FUNCTION_LIST.C_GetMechanismInfo as _getMechanismInfo
  {`FunctionListPtr',
   `Int',
   `Int',
   alloca- `MechInfo' peek* } -> `Rv' fromIntegral
#}


rvToStr :: Rv -> String
rvToStr {#const CKR_OK#} = "ok"
rvToStr {#const CKR_ARGUMENTS_BAD#} = "bad arguments"
rvToStr {#const CKR_ATTRIBUTE_READ_ONLY#} = "attribute is read-only"
rvToStr {#const CKR_ATTRIBUTE_TYPE_INVALID#} = "invalid attribute type specified in template"
rvToStr {#const CKR_ATTRIBUTE_VALUE_INVALID#} = "invalid attribute value specified in template"
rvToStr {#const CKR_BUFFER_TOO_SMALL#} = "buffer too small"
rvToStr {#const CKR_CRYPTOKI_NOT_INITIALIZED#} = "cryptoki not initialized"
rvToStr {#const CKR_DATA_INVALID#} = "data invalid"
rvToStr {#const CKR_DEVICE_ERROR#} = "device error"
rvToStr {#const CKR_DEVICE_MEMORY#} = "device memory"
rvToStr {#const CKR_DEVICE_REMOVED#} = "device removed"
rvToStr {#const CKR_DOMAIN_PARAMS_INVALID#} = "invalid domain parameters"
rvToStr {#const CKR_ENCRYPTED_DATA_INVALID#} = "encrypted data is invalid"
rvToStr {#const CKR_ENCRYPTED_DATA_LEN_RANGE#} = "encrypted data length not in range"
rvToStr {#const CKR_FUNCTION_CANCELED#} = "function canceled"
rvToStr {#const CKR_FUNCTION_FAILED#} = "function failed"
rvToStr {#const CKR_GENERAL_ERROR#} = "general error"
rvToStr {#const CKR_HOST_MEMORY#} = "host memory"
rvToStr {#const CKR_KEY_FUNCTION_NOT_PERMITTED#} = "key function not permitted"
rvToStr {#const CKR_KEY_HANDLE_INVALID#} = "key handle invalid"
rvToStr {#const CKR_KEY_SIZE_RANGE#} = "key size range"
rvToStr {#const CKR_KEY_TYPE_INCONSISTENT#} = "key type inconsistent"
rvToStr {#const CKR_MECHANISM_INVALID#} = "invalid mechanism"
rvToStr {#const CKR_MECHANISM_PARAM_INVALID#} = "invalid mechanism parameter"
rvToStr {#const CKR_OPERATION_ACTIVE#} = "there is already an active operation in-progress"
rvToStr {#const CKR_OPERATION_NOT_INITIALIZED#} = "operation was not initialized"
rvToStr {#const CKR_PIN_EXPIRED#} = "PIN is expired, you need to setup a new PIN"
rvToStr {#const CKR_PIN_INCORRECT#} = "PIN is incorrect, authentication failed"
rvToStr {#const CKR_PIN_LOCKED#} = "PIN is locked, authentication failed"
rvToStr {#const CKR_SESSION_CLOSED#} = "session was closed in a middle of operation"
rvToStr {#const CKR_SESSION_COUNT#} = "session count"
rvToStr {#const CKR_SESSION_HANDLE_INVALID#} = "session handle is invalid"
rvToStr {#const CKR_SESSION_PARALLEL_NOT_SUPPORTED#} = "parallel session not supported"
rvToStr {#const CKR_SESSION_READ_ONLY#} = "session is read-only"
rvToStr {#const CKR_SESSION_READ_ONLY_EXISTS#} = "read-only session exists, SO cannot login"
rvToStr {#const CKR_SESSION_READ_WRITE_SO_EXISTS#} = "read-write SO session exists"
rvToStr {#const CKR_SLOT_ID_INVALID#} = "slot id invalid"
rvToStr {#const CKR_TEMPLATE_INCOMPLETE#} = "provided template is incomplete"
rvToStr {#const CKR_TEMPLATE_INCONSISTENT#} = "provided template is inconsistent"
rvToStr {#const CKR_TOKEN_NOT_PRESENT#} = "token not present"
rvToStr {#const CKR_TOKEN_NOT_RECOGNIZED#} = "token not recognized"
rvToStr {#const CKR_TOKEN_WRITE_PROTECTED#} = "token is write protected"
rvToStr {#const CKR_UNWRAPPING_KEY_HANDLE_INVALID#} = "unwrapping key handle invalid"
rvToStr {#const CKR_UNWRAPPING_KEY_SIZE_RANGE#} = "unwrapping key size not in range"
rvToStr {#const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT#} = "unwrapping key type inconsistent"
rvToStr {#const CKR_USER_NOT_LOGGED_IN#} = "user needs to be logged in to perform this operation"
rvToStr {#const CKR_USER_ALREADY_LOGGED_IN#} = "user already logged in"
rvToStr {#const CKR_USER_ANOTHER_ALREADY_LOGGED_IN#} = "another user already logged in, first another user should be logged out"
rvToStr {#const CKR_USER_PIN_NOT_INITIALIZED#} = "user PIN not initialized, need to setup PIN first"
rvToStr {#const CKR_USER_TOO_MANY_TYPES#} = "cannot login user, somebody should logout first"
rvToStr {#const CKR_USER_TYPE_INVALID#} = "invalid value for user type"
rvToStr {#const CKR_WRAPPED_KEY_INVALID#} = "wrapped key invalid"
rvToStr {#const CKR_WRAPPED_KEY_LEN_RANGE#} = "wrapped key length not in range"
rvToStr rv = "unknown value for error " ++ (show rv)


-- Attributes

{#enum define ClassType {
    CKO_DATA as Data,
    CKO_CERTIFICATE as Certificate,
    CKO_PUBLIC_KEY as PublicKey,
    CKO_PRIVATE_KEY as PrivateKey,
    CKO_SECRET_KEY as SecretKey,
    CKO_HW_FEATURE as HWFeature,
    CKO_DOMAIN_PARAMETERS as DomainParameters,
    CKO_MECHANISM as Mechanism
} deriving (Show, Eq)
#}

{#enum define KeyTypeValue {
    CKK_RSA as RSA,
    CKK_DSA as DSA,
    CKK_DH as DH,
    CKK_ECDSA as ECDSA,
    CKK_EC as EC,
    CKK_AES as AES
    } deriving (Show, Eq) #}

{#enum define AttributeType {
    CKA_CLASS as ClassType,
    CKA_KEY_TYPE as KeyTypeType,
    CKA_LABEL as LabelType,
    CKA_MODULUS_BITS as ModulusBitsType,
    CKA_MODULUS as ModulusType,
    CKA_PUBLIC_EXPONENT as PublicExponentType,
    CKA_PRIVATE_EXPONENT as PrivateExponentType,
    CKA_PRIME_1 as Prime1Type,
    CKA_PRIME_2 as Prime2Type,
    CKA_EXPONENT_1 as Exponent1Type,
    CKA_EXPONENT_2 as Exponent2Type,
    CKA_COEFFICIENT as CoefficientType,
    CKA_TOKEN as TokenType,
    CKA_DECRYPT as DecryptType
    } deriving (Show, Eq) #}

data Attribute = Class ClassType
    | KeyType KeyTypeValue
    | Label String
    | ModulusBits Int
    | Token Bool
    | Decrypt Bool
    | Modulus Integer
    | PublicExponent Integer
    deriving (Show)

data LlAttribute = LlAttribute {
    attributeType :: AttributeType,
    attributeValuePtr :: Ptr (),
    attributeSize :: {#type CK_ULONG#}
}

instance Storable LlAttribute where
    sizeOf _ = {#sizeof CK_ATTRIBUTE_TYPE#} + {#sizeof CK_VOID_PTR#} + {#sizeof CK_ULONG#}
    alignment _ = 1
    poke p x = do
        poke (p `plusPtr` 0) (fromEnum $ attributeType x)
        poke (p `plusPtr` {#sizeof CK_ATTRIBUTE_TYPE#}) (attributeValuePtr x :: {#type CK_VOID_PTR#})
        poke (p `plusPtr` ({#sizeof CK_ATTRIBUTE_TYPE#} + {#sizeof CK_VOID_PTR#})) (attributeSize x)
    peek p = do
        attrType <- peek (p `plusPtr` 0) :: IO {#type CK_ATTRIBUTE_TYPE#}
        valPtr <- peek (p `plusPtr` {#sizeof CK_ATTRIBUTE_TYPE#})
        valSize <- peek (p `plusPtr` ({#sizeof CK_ATTRIBUTE_TYPE#} + {#sizeof CK_VOID_PTR#}))
        return $ LlAttribute (toEnum $ fromIntegral attrType) valPtr valSize


_attrType :: Attribute -> AttributeType
_attrType (Class _) = ClassType
_attrType (KeyType _) = KeyTypeType
_attrType (Label _) = LabelType
_attrType (ModulusBits _) = ModulusBitsType
_attrType (Token _) = TokenType


_valueSize :: Attribute -> Int
_valueSize (Class _) = {#sizeof CK_OBJECT_CLASS#}
_valueSize (KeyType _) = {#sizeof CK_KEY_TYPE#}
_valueSize (Label l) = BU8.length $ BU8.fromString l
_valueSize (ModulusBits _) = {#sizeof CK_ULONG#}
_valueSize (Token _) = {#sizeof CK_BBOOL#}


_pokeValue :: Attribute -> Ptr () -> IO ()
_pokeValue (Class c) ptr = poke (castPtr ptr :: Ptr {#type CK_OBJECT_CLASS#}) (fromIntegral $ fromEnum c)
_pokeValue (KeyType k) ptr = poke (castPtr ptr :: Ptr {#type CK_KEY_TYPE#}) (fromIntegral $ fromEnum k)
_pokeValue (Label l) ptr = unsafeUseAsCStringLen (BU8.fromString l) $ \(src, len) -> copyBytes ptr (castPtr src :: Ptr ()) len
_pokeValue (ModulusBits l) ptr = poke (castPtr ptr :: Ptr {#type CK_ULONG#}) (fromIntegral l :: {#type CK_KEY_TYPE#})
_pokeValue (Token b) ptr = poke (castPtr ptr :: Ptr {#type CK_BBOOL#}) (fromBool b :: {#type CK_BBOOL#})


_pokeValues :: [Attribute] -> Ptr () -> IO ()
_pokeValues [] p = return ()
_pokeValues (a:rem) p = do
    _pokeValue a p
    _pokeValues rem (p `plusPtr` (_valueSize a))


_valuesSize :: [Attribute] -> Int
_valuesSize attribs = foldr (+) 0 (map (_valueSize) attribs)


_makeLowLevelAttrs :: [Attribute] -> Ptr () -> [LlAttribute]
_makeLowLevelAttrs [] valuePtr = []
_makeLowLevelAttrs (a:rem) valuePtr =
    let valuePtr' = valuePtr `plusPtr` (_valueSize a)
        llAttr = LlAttribute {attributeType=_attrType a, attributeValuePtr=valuePtr, attributeSize=(fromIntegral $ _valueSize a)}
    in
        llAttr:(_makeLowLevelAttrs rem valuePtr')


_withAttribs :: [Attribute] -> (Ptr LlAttribute -> IO a) -> IO a
_withAttribs attribs f = do
    allocaBytes (_valuesSize attribs) $ \valuesPtr -> do
        _pokeValues attribs valuesPtr
        allocaArray (length attribs) $ \attrsPtr -> do
            pokeArray attrsPtr (_makeLowLevelAttrs attribs valuesPtr)
            f attrsPtr


_peekBigInt :: Ptr () -> CULong -> IO Integer
_peekBigInt ptr len = do
    arr <- peekArray (fromIntegral len) (castPtr ptr :: Ptr Word8)
    return $ foldl (\acc v -> (fromIntegral v) + (acc * 256)) 0 arr


_llAttrToAttr :: LlAttribute -> IO Attribute
_llAttrToAttr (LlAttribute ClassType ptr len) = do
    val <- peek (castPtr ptr :: Ptr {#type CK_OBJECT_CLASS#})
    return (Class $ toEnum $ fromIntegral val)
_llAttrToAttr (LlAttribute ModulusType ptr len) = do
    val <- _peekBigInt ptr len
    return (Modulus val)
_llAttrToAttr (LlAttribute PublicExponentType ptr len) = do
    val <- _peekBigInt ptr len
    return (PublicExponent val)
_llAttrToAttr (LlAttribute DecryptType ptr len) = do
    val <- peek (castPtr ptr :: Ptr {#type CK_BBOOL#})
    return $ Decrypt(val /= 0)


-- High level API starts here


data Library = Library {
    libraryHandle :: DL,
    functionListPtr :: FunctionListPtr
}


data Session = Session SessionHandle FunctionListPtr


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


releaseLibrary lib = do
    rv <- finalize $ functionListPtr lib
    dlclose $ libraryHandle lib


getInfo :: Library -> IO Info
getInfo (Library _ functionListPtr) = do
    (rv, info) <- getInfo' functionListPtr
    if rv /= 0
        then fail $ "failed to get library information " ++ (rvToStr rv)
        else return info


getSlotList :: Library -> Bool -> Int -> IO [CULong]
getSlotList (Library _ functionListPtr) active num = do
    (rv, slots) <- getSlotList' functionListPtr active num
    if rv /= 0
        then fail $ "failed to get list of slots " ++ (rvToStr rv)
        else return slots


getSlotInfo :: Library -> Int -> IO SlotInfo
getSlotInfo (Library _ functionListPtr) slotId = do
    (rv, slotInfo) <- getSlotInfo' functionListPtr slotId
    if rv /= 0
        then fail $ "failed to get slot information " ++ (rvToStr rv)
        else return slotInfo


getTokenInfo :: Library -> Int -> IO TokenInfo
getTokenInfo (Library _ functionListPtr) slotId = do
    (rv, slotInfo) <- getTokenInfo' functionListPtr slotId
    if rv /= 0
        then fail $ "failed to get token information " ++ (rvToStr rv)
        else return slotInfo


_openSessionEx :: Library -> Int -> Int -> IO Session
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


withSession :: Library -> Int -> Int -> (Session -> IO a) -> IO a
withSession lib slotId flags f = do
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


findObjects :: Session -> [Attribute] -> IO [ObjectHandle]
findObjects session attribs = do
    _findObjectsInitEx session attribs
    finally (_findObjectsEx session) (_findObjectsFinalEx session)


generateKeyPair :: Session -> Int -> [Attribute] -> [Attribute] -> IO (ObjectHandle, ObjectHandle)
generateKeyPair (Session sessionHandle functionListPtr) mechType pubKeyAttrs privKeyAttrs = do
    (rv, pubKeyHandle, privKeyHandle) <- _generateKeyPair functionListPtr sessionHandle mechType pubKeyAttrs privKeyAttrs
    if rv /= 0
        then fail $ "failed to generate key pair: " ++ (rvToStr rv)
        else return (pubKeyHandle, privKeyHandle)


getObjectAttr :: Session -> ObjectHandle -> AttributeType -> IO Attribute
getObjectAttr (Session sessionHandle functionListPtr) objHandle attrType = do
    alloca $ \attrPtr -> do
        poke attrPtr (LlAttribute attrType nullPtr 0)
        rv <- {#call unsafe CK_FUNCTION_LIST.C_GetAttributeValue#} functionListPtr sessionHandle objHandle attrPtr 1
        attrWithLen <- peek attrPtr
        allocaBytes (fromIntegral $ attributeSize attrWithLen) $ \attrVal -> do
            poke attrPtr (LlAttribute attrType attrVal (attributeSize attrWithLen))
            rv <- {#call unsafe CK_FUNCTION_LIST.C_GetAttributeValue#} functionListPtr sessionHandle objHandle attrPtr 1
            if rv /= 0
                then fail $ "failed to get attribute: " ++ (rvToStr rv)
                else do
                    llAttr <- peek attrPtr
                    _llAttrToAttr llAttr


getModulus :: Session -> ObjectHandle -> IO Integer
getModulus sess objHandle = do
    (Modulus m) <- getObjectAttr sess objHandle ModulusType
    return m

getPublicExponent :: Session -> ObjectHandle -> IO Integer
getPublicExponent sess objHandle = do
    (PublicExponent v) <- getObjectAttr sess objHandle PublicExponentType
    return v


login :: Session -> UserType -> BU8.ByteString -> IO ()
login (Session sessionHandle functionListPtr) userType pin = do
    rv <- _login functionListPtr sessionHandle userType pin
    if rv /= 0
        then fail $ "login failed: " ++ (rvToStr rv)
        else return ()


{#enum define MechType {
    CKM_RSA_PKCS_KEY_PAIR_GEN as RsaPkcsKeyPairGen,
    CKM_RSA_PKCS as RsaPkcs,
    CKM_AES_ECB as AesEcb,
    CKM_AES_CBC as AesCbc,
    CKM_AES_MAC as AesMac,
    CKM_AES_MAC_GENERAL as AesMacGeneral,
    CKM_AES_CBC_PAD as AesCbcPad,
    CKM_AES_CTR as AesCtr
    } deriving (Eq) #}


_decryptInit :: MechType -> Session -> ObjectHandle -> IO ()
_decryptInit mechType (Session sessionHandle functionListPtr) obj = do
    alloca $ \mechPtr -> do
        poke mechPtr (Mech {mechType = fromEnum mechType, mechParamPtr = nullPtr, mechParamSize = 0})
        rv <- {#call unsafe CK_FUNCTION_LIST.C_DecryptInit#} functionListPtr sessionHandle mechPtr obj
        if rv /= 0
            then fail $ "failed to initiate decryption: " ++ (rvToStr rv)
            else return ()


decrypt :: MechType -> Session -> ObjectHandle -> BS.ByteString -> IO BS.ByteString
decrypt mechType (Session sessionHandle functionListPtr) obj encData = do
    _decryptInit mechType (Session sessionHandle functionListPtr) obj
    unsafeUseAsCStringLen encData $ \(encDataPtr, encDataLen) -> do
        putStrLn $ "in data len " ++ (show encDataLen)
        putStrLn $ show encData
        allocaBytes encDataLen $ \outDataPtr -> do
            alloca $ \outDataLenPtr -> do
                poke outDataLenPtr (fromIntegral encDataLen)
                rv <- {#call unsafe CK_FUNCTION_LIST.C_Decrypt#} functionListPtr sessionHandle (castPtr encDataPtr) (fromIntegral encDataLen) outDataPtr outDataLenPtr
                if rv /= 0
                    then fail $ "failed to decrypt: " ++ (rvToStr rv)
                    else do
                        outDataLen <- peek outDataLenPtr
                        res <- BS.packCStringLen (castPtr outDataPtr, fromIntegral outDataLen)
                        return res


_encryptInit :: MechType -> Session -> ObjectHandle -> IO ()
_encryptInit mechType (Session sessionHandle functionListPtr) obj = do
    alloca $ \mechPtr -> do
        poke mechPtr (Mech {mechType = fromEnum mechType, mechParamPtr = nullPtr, mechParamSize = 0})
        rv <- {#call unsafe CK_FUNCTION_LIST.C_EncryptInit#} functionListPtr sessionHandle mechPtr obj
        if rv /= 0
            then fail $ "failed to initiate decryption: " ++ (rvToStr rv)
            else return ()


encrypt :: MechType -> Session -> ObjectHandle -> BS.ByteString -> IO BS.ByteString
encrypt mechType (Session sessionHandle functionListPtr) obj encData = do
    _encryptInit mechType (Session sessionHandle functionListPtr) obj
    let outLen = 1000
    unsafeUseAsCStringLen encData $ \(encDataPtr, encDataLen) -> do
        allocaBytes outLen $ \outDataPtr -> do
            alloca $ \outDataLenPtr -> do
                poke outDataLenPtr (fromIntegral outLen)
                rv <- {#call unsafe CK_FUNCTION_LIST.C_Encrypt#} functionListPtr sessionHandle (castPtr encDataPtr) (fromIntegral encDataLen) outDataPtr outDataLenPtr
                if rv /= 0
                    then fail $ "failed to decrypt: " ++ (rvToStr rv)
                    else do
                        outDataLen <- peek outDataLenPtr
                        res <- BS.packCStringLen (castPtr outDataPtr, fromIntegral outDataLen)
                        return res


unwrapKey :: MechType -> Session -> ObjectHandle -> BS.ByteString -> [Attribute] -> IO ObjectHandle
unwrapKey mechType (Session sessionHandle functionListPtr) key wrappedKey template = do
    _withAttribs template $ \attribsPtr -> do
        alloca $ \mechPtr -> do
            poke mechPtr (Mech {mechType = fromEnum mechType, mechParamPtr = nullPtr, mechParamSize = 0})
            unsafeUseAsCStringLen wrappedKey $ \(wrappedKeyPtr, wrappedKeyLen) -> do
                alloca $ \unwrappedKeyPtr -> do
                    rv <- {#call unsafe CK_FUNCTION_LIST.C_UnwrapKey#} functionListPtr sessionHandle mechPtr key (castPtr wrappedKeyPtr) (fromIntegral wrappedKeyLen) attribsPtr (fromIntegral $ length template) unwrappedKeyPtr
                    if rv /= 0
                        then fail $ "failed to unwrap key: " ++ (rvToStr rv)
                        else do
                            unwrappedKey <- peek unwrappedKeyPtr
                            return unwrappedKey


getMechanismList :: Library -> Int -> Int -> IO [CULong]
getMechanismList (Library _ functionListPtr) slotId maxMechanisms = do
    (rv, types) <- _getMechanismList functionListPtr slotId maxMechanisms
    if rv /= 0
        then fail $ "failed to get list of mechanisms: " ++ (rvToStr rv)
        else return types


getMechanismInfo :: Library -> Int -> Int -> IO MechInfo
getMechanismInfo (Library _ functionListPtr) slotId mechId = do
    (rv, types) <- _getMechanismInfo functionListPtr slotId mechId
    if rv /= 0
        then fail $ "failed to get mechanism information: " ++ (rvToStr rv)
        else return types

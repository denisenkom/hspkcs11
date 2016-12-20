{-# LANGUAGE ForeignFunctionInterface #-}
module Pkcs11 where
import Foreign
import Foreign.Marshal.Utils
import Foreign.Marshal.Alloc
import Foreign.C
import Foreign.Ptr
import System.Posix.DynamicLinker
import Control.Monad

#include "pkcs11import.h"

{-
 Currently cannot use c2hs structure alignment and offset detector since it does not support pragma pack
 which is required by PKCS11, which is using 1 byte packing
 https://github.com/haskell/c2hs/issues/172
-}

serialSession = {#const CKF_SERIAL_SESSION#} :: Int

type SlotId = {#type CK_SLOT_ID#}
type Rv = {#type CK_RV#}
type CK_BYTE = {#type CK_BYTE#}
type CK_FLAGS = {#type CK_FLAGS#}
type GetFunctionListFunPtr = {#type CK_C_GetFunctionList#}
type GetSlotListFunPtr = {#type CK_C_GetSlotList#}
type NotifyFunPtr = {#type CK_NOTIFY#}

{#pointer *CK_FUNCTION_LIST as FunctionListPtr#}
{#pointer *CK_INFO as InfoPtr -> Info#}
{#pointer *CK_SLOT_INFO as SlotInfoPtr -> SlotInfo#}

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
  sizeOf _ = (2+32+4+32+10+2){-#sizeof CK_INFO#-}
  alignment _ = 1{-#alignof CK_INFO#-}
  peek p = do
    ver <- peek (p `plusPtr` {#offsetof CK_INFO->cryptokiVersion#}) :: IO Version
    manufacturerId <- peekCStringLen ((p `plusPtr` 2{-#offsetof CK_INFO->manufacturerID#-}), 32)
    flags <- (\ptr -> do {C2HSImp.peekByteOff ptr (2+32) :: IO C2HSImp.CULong}) p
    --flags <- {#get CK_INFO->flags#} p
    libraryDescription <- peekCStringLen ((p `plusPtr` (2+32+4+10){-#offsetof CK_INFO->libraryDescription#-}), 32)
    --libraryDescription <- {# get CK_INFO->libraryDescription #} p
    libVer <- peek (p `plusPtr` (2+32+4+32+10){-#offsetof CK_INFO->libraryVersion#-}) :: IO Version
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
  sizeOf _ = (64+32+4+2+2){-#sizeof CK_INFO#-}
  alignment _ = 1{-#alignof CK_INFO#-}
  peek p = do
    description <- peekCStringLen ((p `plusPtr` 0{-#offsetof CK_SLOT_INFO->slotDescription#-}), 64)
    manufacturerId <- peekCStringLen ((p `plusPtr` 64{-#offsetof CK_SLOT_INFO->manufacturerID#-}), 32)
    flags <- C2HSImp.peekByteOff p (64+32) :: IO C2HSImp.CULong
    hwVer <- peek (p `plusPtr` (64+32+4){-#offsetof CK_SLOT_INFO->hardwareVersion#-}) :: IO Version
    fwVer <- peek (p `plusPtr` (64+32+4+2){-#offsetof CK_SLOT_INFO->firmwareVersion#-}) :: IO Version
    return SlotInfo {slotInfoDescription=description,
                     slotInfoManufacturerId=manufacturerId,
                     slotInfoFlags=fromIntegral flags,
                     slotInfoHardwareVersion=hwVer,
                     slotInfoFirmwareVersion=fwVer
                     }


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


openSession' functionListPtr slotId flags =
  alloca $ \slotIdPtr -> do
    res <- {#call unsafe CK_FUNCTION_LIST.C_OpenSession#} functionListPtr (fromIntegral slotId) (fromIntegral flags) nullPtr nullFunPtr slotIdPtr
    slotId <- peek slotIdPtr
    return (fromIntegral res, fromIntegral slotId)


{#fun unsafe CK_FUNCTION_LIST.C_Finalize as finalize
 {`FunctionListPtr',
  alloca- `()' } -> `Rv' fromIntegral#}


getFunctionList :: GetFunctionListFunPtr -> IO ((Rv), (FunctionListPtr))
getFunctionList getFunctionListPtr =
  alloca $ \funcListPtrPtr -> do
    res <- (getFunctionList'_ getFunctionListPtr) funcListPtrPtr
    funcListPtr <- peek funcListPtrPtr
    return (fromIntegral res, funcListPtr)


findObjectsInit functionListPtr session = do
  res <- {#call unsafe CK_FUNCTION_LIST.C_FindObjectsInit#} functionListPtr session nullPtr (fromIntegral 0)
  return (fromIntegral res)


findObjects functionListPtr session maxObjects = do
  alloca $ \arrayLenPtr -> do
    poke arrayLenPtr (fromIntegral 0)
    allocaArray maxObjects $ \array -> do
      res <- {#call unsafe CK_FUNCTION_LIST.C_FindObjects#} functionListPtr session array (fromIntegral maxObjects) arrayLenPtr
      arrayLen <- peek arrayLenPtr
      objectHandles <- peekArray (fromIntegral arrayLen) array
      return (fromIntegral res, objectHandles)


{#fun unsafe CK_FUNCTION_LIST.C_FindObjectsFinal as findObjectsFinal
 {`FunctionListPtr',
  `CULong' } -> `Rv' fromIntegral#}


rvToStr :: Rv -> String
rvToStr {#const CKR_OK#} = "ok"
rvToStr {#const CKR_ARGUMENTS_BAD#} = "bad arguments"
rvToStr {#const CKR_FUNCTION_FAILED#} = "function failed"
rvToStr {#const CKR_GENERAL_ERROR#} = "general error"
rvToStr {#const CKR_HOST_MEMORY#} = "host memory"
rvToStr {#const CKR_CRYPTOKI_NOT_INITIALIZED#} = "cryptoki not initialized"
rvToStr {#const CKR_DEVICE_MEMORY#} = "device memory"
rvToStr {#const CKR_DEVICE_REMOVED#} = "device removed"
rvToStr {#const CKR_SESSION_COUNT#} = "session count"
rvToStr {#const CKR_SESSION_PARALLEL_NOT_SUPPORTED#} = "parallel session not supported"
rvToStr {#const CKR_SESSION_READ_WRITE_SO_EXISTS#} = "read-write SO session exists"
rvToStr {#const CKR_SLOT_ID_INVALID#} = "slot id invalid"
rvToStr {#const CKR_TOKEN_NOT_PRESENT#} = "token not present"
rvToStr {#const CKR_TOKEN_NOT_RECOGNIZED#} = "token not recognized"
rvToStr {#const CKR_TOKEN_WRITE_PROTECTED#} = "token write protected"


-- High level API starts here


data Library = Library {
    libraryHandle :: DL,
    functionListPtr :: FunctionListPtr
}


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


openSession :: Library -> Int -> Int -> IO Int
openSession (Library _ functionListPtr) slotId flags = do
    (rv, sessionHandle) <- openSession' functionListPtr slotId flags
    if rv /= 0
        then fail $ "failed to open slot: " ++ (rvToStr rv)
        else return sessionHandle

module Bindings.Pkcs11.Shared where
import Bindings.Pkcs11
import Foreign.Ptr (Ptr,castPtr,nullPtr)
import Foreign.C.Types (CULong, CUChar)
import qualified Data.ByteString as BS
import Foreign.Marshal.Alloc (allocaBytes)
import Control.Monad (when)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)


-- | Represent session. Created by 'withSession' function.
data Session =
  Session SessionHandle
          FunctionListPtr

data Object =
  Object FunctionListPtr
         SessionHandle
         ObjectHandle
  deriving (Show)

-- | Initialize a multi-part decryption operation using provided mechanism and key.
decryptInit :: Mech -> Object -> IO ()
decryptInit mech (Object funcListPtr sessionHandle objHandle) = do
  rv <- decryptInit' funcListPtr sessionHandle mech objHandle
  when (rv /= 0) $ fail $ "failed to initiate decryption: " ++ rvToStr rv

varLenGet :: Maybe CULong -> ((Ptr CUChar, CULong) -> IO (Rv, CULong)) -> IO (Rv, BS.ByteString)
varLenGet Nothing func = do
  (rv, needLen) <- func (nullPtr, 0)
  if rv /= 0
    then fail $ "failed to query resulting size for operation" ++ rvToStr rv
    else allocaBytes (fromIntegral needLen) $ \outDataPtr -> do
           (rv, actualLen) <- func (outDataPtr, needLen)
           if rv == errBufferTooSmall
             then fail "function returned CKR_BUFFER_TOO_SMALL when it shoudln't"
             else if rv /= 0
                    then return (rv, BS.empty)
                    else do
                      resBs <- BS.packCStringLen (castPtr outDataPtr, fromIntegral actualLen)
                      return (rv, resBs)
varLenGet (Just len) func =
  allocaBytes (fromIntegral len) $ \outDataPtr -> do
    (rv, actualLen) <- func (outDataPtr, len)
    if rv /= 0
      then return (rv, BS.empty)
      else do
        resBs <- BS.packCStringLen (castPtr outDataPtr, fromIntegral actualLen)
        return (rv, resBs)

encryptUpdate (Session sessHandle funcListPtr) inData maybeOutLen =
  unsafeUseAsCStringLen inData $ \(inDataPtr, inDataLen) -> do
    (rv, bs) <-
      varLenGet maybeOutLen $
      uncurry (encryptUpdate' funcListPtr sessHandle (castPtr inDataPtr) (fromIntegral inDataLen))
    if rv /= 0
      then fail $ "failed to encrypt part: " ++ rvToStr rv
      else return bs

decryptUpdate (Session sessHandle funcListPtr) inData maybeOutLen =
  unsafeUseAsCStringLen inData $ \(inDataPtr, inDataLen) -> do
    (rv, bs) <-
      varLenGet maybeOutLen $
      uncurry (decryptUpdate' funcListPtr sessHandle (castPtr inDataPtr) (fromIntegral inDataLen))
    if rv /= 0
      then fail $ "failed to decrypt part: " ++ rvToStr rv
      else return bs

encryptFinal (Session sessHandle funcListPtr) maybeOutLen = do
  (rv, bs) <- varLenGet maybeOutLen $ uncurry (encryptFinal' funcListPtr sessHandle)
  if rv /= 0
    then fail $ "failed to complete encryption: " ++ rvToStr rv
    else return bs

decryptFinal (Session sessHandle funcListPtr) maybeOutLen = do
  (rv, bs) <- varLenGet maybeOutLen $ uncurry (decryptFinal' funcListPtr sessHandle)
  if rv /= 0
    then fail $ "failed to complete decryption: " ++ rvToStr rv
    else return bs

digestInit :: Mech -> Session -> IO ()
digestInit mech (Session sessHandle funcListPtr) = do
  rv <- digestInit' funcListPtr sessHandle mech
  when (rv /= 0) $ fail $ "failed to initialize digest operation: " ++ rvToStr rv

digestUpdate :: Session -> BS.ByteString -> IO ()
digestUpdate (Session sessHandle funcListPtr) inData =
  unsafeUseAsCStringLen inData $ \(inDataPtr, inDataLen) -> do
    rv <- digestUpdate' funcListPtr sessHandle (castPtr inDataPtr) (fromIntegral inDataLen)
    when (rv /= 0) $ fail $ "failed to add data to digest operation: " ++ rvToStr rv

digestKey :: Mech -> Session -> ObjectHandle -> IO ()
digestKey mech (Session sessHandle funcListPtr) key = do
  rv <- digestKey' funcListPtr sessHandle key
  when (rv /= 0) $ fail $ "failed to add key to digest operation: " ++ rvToStr rv

digestFinal (Session sessHandle funcListPtr) maybeOutLen = do
  (rv, bs) <- varLenGet maybeOutLen $ uncurry (digestFinal' funcListPtr sessHandle)
  if rv /= 0
    then fail $ "failed to complete digest operation: " ++ rvToStr rv
    else return bs

-- | Initialize multi-part encryption operation.
encryptInit ::
     Mech -- ^ Mechanism to use for encryption.
  -> Object -- ^ Encryption key.
  -> IO ()
encryptInit mech (Object functionListPtr sessionHandle obj) = do
  rv <- encryptInit' functionListPtr sessionHandle mech obj
  when (rv /= 0) $ fail $ "failed to initiate decryption: " ++ rvToStr rv

signInit :: Mech -> Object -> IO ()
signInit mech (Object funcListPtr sessHandle objHandle) = do
  rv <- signInit' funcListPtr sessHandle mech objHandle
  when (rv /= 0) $ fail $ "failed to initialize signing operation: " ++ rvToStr rv

signUpdate (Session sessHandle funcListPtr) inData =
  unsafeUseAsCStringLen inData $ \(inDataPtr, inDataLen) -> do
    rv <- signUpdate' funcListPtr sessHandle (castPtr inDataPtr) (fromIntegral inDataLen)
    when (rv /= 0) $ fail $ "failed to sign part: " ++ rvToStr rv

signFinal (Session sessHandle funcListPtr) maybeOutLen = do
  (rv, bs) <-
    varLenGet maybeOutLen $ uncurry (signFinal' funcListPtr sessHandle)
  if rv /= 0
    then fail $ "failed to finalize signing: " ++ rvToStr rv
    else return bs

verifyInit :: Mech -> Object -> IO ()
verifyInit mech (Object funcListPtr sessHandle objHandle) = do
  rv <- verifyInit' funcListPtr sessHandle mech objHandle
  when (rv /= 0) $ fail $ "failed to initialize verify operation: " ++ rvToStr rv

signRecoverInit :: Mech -> Object -> IO ()
signRecoverInit mech (Object funcListPtr sessHandle objHandle) = do
  rv <- signRecoverInit' funcListPtr sessHandle mech objHandle
  when (rv /= 0) $ fail $ "failed to initialize signing with recovery operation: " ++ rvToStr rv

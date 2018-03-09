-- | This module contains lazy versions of functions.
module System.Crypto.Pkcs11.Lazy (
  encrypt
) where
import System.Crypto.Pkcs11 hiding (encrypt)
import Bindings.Pkcs11.Attribs
import Bindings.Pkcs11.Shared
import qualified Data.ByteString as BS
import Data.ByteString.Lazy


defaultChunkSize = 4096


lazyEncryptList :: Session -> [BS.ByteString] -> IO [BS.ByteString]
lazyEncryptList sess (c:rest) = do
  encC <- encryptUpdate sess c (Just defaultChunkSize)
  encRest <- lazyEncryptList sess rest
  return (encC : encRest)

lazyEncryptList sess [] = do
  last <- encryptFinal sess (Just defaultChunkSize)
  return [last]


encrypt :: Mech -> Object -> ByteString -> IO ByteString
encrypt mech (Object functionListPtr sessionHandle keyHandle) bsl = do
  encryptInit mech (Object functionListPtr sessionHandle keyHandle)
  res <- lazyEncryptList (Session sessionHandle functionListPtr) (toChunks bsl)
  return $ fromChunks res

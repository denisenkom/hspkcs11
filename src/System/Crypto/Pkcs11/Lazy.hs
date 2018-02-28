-- | This module contains lazy versions of functions.
module System.Crypto.Pkcs11.Lazy (
  encrypt
) where
import System.Crypto.Pkcs11 hiding (encrypt)
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


encrypt :: Session -> ByteString -> IO ByteString
encrypt sess bsl = do
  res <- lazyEncryptList sess (toChunks bsl)
  return $ fromChunks res


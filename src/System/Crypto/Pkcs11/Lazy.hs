-- | This module contains lazy versions of functions.
module System.Crypto.Pkcs11.Lazy
  ( encrypt
  , decrypt
  , sign
  ) where

import Bindings.Pkcs11.Attribs
import Bindings.Pkcs11.Shared
import qualified Data.ByteString as BS
import Data.ByteString.Lazy
import System.Crypto.Pkcs11 hiding (decrypt, encrypt, sign)

defaultChunkSize = 4096

encrypt :: Mech -> Object -> ByteString -> IO ByteString
encrypt mech (Object functionListPtr sessionHandle keyHandle) bsl = do
  encryptInit mech (Object functionListPtr sessionHandle keyHandle)
  res <- mapM (\bs -> encryptUpdate (Session sessionHandle functionListPtr) bs (Just defaultChunkSize)) (toChunks bsl)
  last <- encryptFinal (Session sessionHandle functionListPtr) (Just defaultChunkSize)
  return $ fromChunks (res ++ [last])

decrypt :: Mech -> Object -> ByteString -> IO ByteString
decrypt mech (Object functionListPtr sessionHandle keyHandle) bsl = do
  decryptInit mech (Object functionListPtr sessionHandle keyHandle)
  res <- mapM (\bs -> decryptUpdate (Session sessionHandle functionListPtr) bs (Just defaultChunkSize)) (toChunks bsl)
  last <- decryptFinal (Session sessionHandle functionListPtr) (Just defaultChunkSize)
  return $ fromChunks (res ++ [last])

sign :: Mech -> Object -> ByteString -> IO BS.ByteString
sign mech (Object functionListPtr sessionHandle keyHandle) bsl = do
  signInit mech (Object functionListPtr sessionHandle keyHandle)
  mapM_ (signUpdate (Session sessionHandle functionListPtr)) (toChunks bsl)
  signFinal (Session sessionHandle functionListPtr) (Just defaultChunkSize)

digest :: Mech -> Object -> ByteString -> IO BS.ByteString
digest mech (Object functionListPtr sessionHandle keyHandle) bsl = do
  digestInit mech (Session sessionHandle functionListPtr)
  mapM_ (digestUpdate (Session sessionHandle functionListPtr)) (toChunks bsl)
  digestFinal (Session sessionHandle functionListPtr) (Just defaultChunkSize)
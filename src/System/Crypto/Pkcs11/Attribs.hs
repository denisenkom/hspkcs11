module System.Crypto.Pkcs11.Attribs (
    Attribute(..)
  , AttributeType(..)
  , ClassType(..)
  , KeyTypeValue(..)
    -- ** Reading object attributes
  , getAttrib
  , getKeyType
  , getTokenFlag
  , getPrivateFlag
  , getSensitiveFlag
  , getEncryptFlag
  , getDecryptFlag
  , getWrapFlag
  , getUnwrapFlag
  , getSignFlag
  , getVerifyFlag
  , getExtractable
  , getModifiable
  , getModulus
  , getPublicExponent
  , getPrime
  , getBase
  , getEcdsaParams
  , getEcPoint
    -- ** Writing attributes
  , setAttributes
) where
import Bindings.Pkcs11
import Bindings.Pkcs11.Attribs
import Foreign.Ptr
import Control.Monad (when)


getTokenFlag = getBoolAttr TokenType

getPrivateFlag = getBoolAttr PrivateType

getSensitiveFlag = getBoolAttr SensitiveType

getEncryptFlag = getBoolAttr EncryptType

getDecryptFlag = getBoolAttr DecryptType

getWrapFlag = getBoolAttr WrapType

getUnwrapFlag = getBoolAttr UnwrapType

getSignFlag = getBoolAttr SignType

getVerifyFlag = getBoolAttr VerifyType

getExtractable = getBoolAttr ExtractableType

getModifiable = getBoolAttr ModifiableType

getModulus :: Object -> IO Integer
getModulus (Object funcListPtr sessHandle objHandle) = do
  (Modulus m) <- getObjectAttr' funcListPtr sessHandle objHandle ModulusType
  return m

getPublicExponent :: Object -> IO Integer
getPublicExponent (Object funcListPtr sessHandle objHandle) = do
  (PublicExponent v) <- getObjectAttr' funcListPtr sessHandle objHandle PublicExponentType
  return v

getPrime (Object funcListPtr sessHandle objHandle) = do
  (Prime p) <- getObjectAttr' funcListPtr sessHandle objHandle PrimeType
  return p

getBase (Object funcListPtr sessHandle objHandle) = do
  (Base p) <- getObjectAttr' funcListPtr sessHandle objHandle BaseType
  return p

getEcdsaParams (Object funcListPtr sessHandle objHandle) = do
  (EcdsaParams bs) <- getObjectAttr' funcListPtr sessHandle objHandle EcParamsType
  return bs

getEcPoint (Object funcListPtr sessHandle objHandle) = do
  (EcPoint bs) <- getObjectAttr' funcListPtr sessHandle objHandle EcPointType
  return bs

getKeyType (Object funcListPtr sessHandle objHandle) = do
  (KeyType kt) <- getObjectAttr' funcListPtr sessHandle objHandle KeyTypeType
  return kt

getAttrib attrType (Object funcListPtr sessHandle objHandle) = getObjectAttr' funcListPtr sessHandle objHandle attrType


-- | Modifies attributes of an object.
setAttributes (Object funcListPtr sessHandle objHandle) attribs =
  _withAttribs attribs $ \attribsPtr -> do
    rv <- setAttributeValue' funcListPtr sessHandle objHandle attribsPtr (fromIntegral $ length attribs)
    when (rv /= 0) $ fail $ "failed to set attributes: " ++ rvToStr rv

module Bindings.Pkcs11.Attribs where
import Bindings.Pkcs11
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as BU8
import Data.ByteString.Unsafe
import Data.List
import Data.Word
import Foreign.C.Types
import Foreign.Marshal.Alloc
import Foreign.Marshal.Array
import Foreign.Marshal.Utils
import Foreign.Ptr
import Foreign.Storable
import Control.Monad (when)

-- | Represents an attribute of an object
data Attribute = Class ClassType -- ^ class of an object, e.g. 'PrivateKey', 'SecretKey'
    | KeyType KeyTypeValue -- ^ e.g. 'RSA' or 'AES'
    | Label String -- ^ object's label
    | Token Bool -- ^ whether object is stored on the token or is a temporary session object
    | Decrypt Bool -- ^ allow/deny encryption function for an object
    | Sign Bool -- ^ allow/deny signing function for an object
    | ModulusBits Int -- ^ number of bits used by modulus, for example in RSA public key
    | Modulus Integer -- ^ modulus value, used by RSA keys
    | PublicExponent Integer -- ^ value of public exponent, used by RSA public keys
    | PrimeBits Int -- ^ number of bits used by prime in classic Diffie-Hellman
    | Prime Integer -- ^ value of prime modulus, used in classic Diffie-Hellman
    | Base Integer -- ^ value of generator, used in classic Diffie-Hellman
    | ValueLen Int -- ^ length in bytes of the corresponding 'Value' attribute
    | Value BS.ByteString -- ^ object's value attribute, for example it is a DER encoded certificate for certificate objects
    | Extractable Bool -- ^ allows or denys extraction of certain attributes of private keys
    | EcParams BS.ByteString -- ^ DER encoded ANSI X9.62 parameters value for elliptic-curve algorithm
    | EcdsaParams BS.ByteString -- ^ DER encoded ANSI X9.62 parameters value for elliptic-curve algorithm
    | EcPoint BS.ByteString -- ^ DER encoded ANSI X9.62 point for elliptic-curve algorithm
    deriving (Show)

-- from http://hackage.haskell.org/package/binary-0.5.0.2/docs/src/Data-Binary.html#unroll
unroll :: Integer -> [Word8]
unroll = unfoldr step
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `shiftR` 8)

_bigIntLen i = length $ unroll i

_pokeBigInt i ptr = pokeArray ptr (unroll i)

_attrType :: Attribute -> AttributeType
_attrType (Class _) = ClassType
_attrType (KeyType _) = KeyTypeType
_attrType (Label _) = LabelType
_attrType (ModulusBits _) = ModulusBitsType
_attrType (PrimeBits _) = PrimeBitsType
_attrType (Token _) = TokenType
_attrType (ValueLen _) = ValueLenType
_attrType (Extractable _) = ExtractableType
_attrType (Value _) = ValueType
_attrType (Prime _) = PrimeType
_attrType (Base _) = BaseType
_attrType (EcParams _) = EcParamsType
_attrType (EcPoint _) = EcPointType

_valueSize :: Attribute -> Int
_valueSize (Class _) = sizeOf (0 :: CK_OBJECT_CLASS)
_valueSize (KeyType _) = sizeOf (0 :: CK_KEY_TYPE)
_valueSize (Label l) = BU8.length $ BU8.fromString l
_valueSize (ModulusBits _) = sizeOf (0 :: CULong)
_valueSize (PrimeBits _) = sizeOf (0 :: CULong)
_valueSize (Token _) = sizeOf (0 :: CK_BBOOL)
_valueSize (ValueLen _) = sizeOf (0 :: CULong)
_valueSize (Extractable _) = sizeOf (0 :: CK_BBOOL)
_valueSize (Value bs) = BS.length bs
_valueSize (Prime p) = _bigIntLen p
_valueSize (Base b) = _bigIntLen b
_valueSize (EcParams bs) = BS.length bs
_valueSize (EcPoint bs) = BS.length bs

_pokeValue :: Attribute -> Ptr () -> IO ()
_pokeValue (Class c) ptr = poke (castPtr ptr :: Ptr CK_OBJECT_CLASS) (fromIntegral $ fromEnum c)
_pokeValue (KeyType k) ptr = poke (castPtr ptr :: Ptr CK_KEY_TYPE) (fromIntegral $ fromEnum k)
_pokeValue (Label l) ptr =
  unsafeUseAsCStringLen (BU8.fromString l) $ \(src, len) -> copyBytes ptr (castPtr src :: Ptr ()) len
_pokeValue (ModulusBits l) ptr = poke (castPtr ptr :: Ptr CULong) (fromIntegral l)
_pokeValue (PrimeBits l) ptr = poke (castPtr ptr :: Ptr CULong) (fromIntegral l)
_pokeValue (Token b) ptr = poke (castPtr ptr :: Ptr CK_BBOOL) (fromBool b :: CK_BBOOL)
_pokeValue (ValueLen l) ptr = poke (castPtr ptr :: Ptr CULong) (fromIntegral l :: CULong)
_pokeValue (Extractable b) ptr = poke (castPtr ptr :: Ptr CK_BBOOL) (fromBool b :: CK_BBOOL)
_pokeValue (Value bs) ptr = unsafeUseAsCStringLen bs $ \(src, len) -> copyBytes ptr (castPtr src :: Ptr ()) len
_pokeValue (Prime p) ptr = _pokeBigInt p (castPtr ptr)
_pokeValue (Base b) ptr = _pokeBigInt b (castPtr ptr)
_pokeValue (EcParams bs) ptr = unsafeUseAsCStringLen bs $ \(src, len) -> copyBytes ptr (castPtr src :: Ptr ()) len
_pokeValue (EcPoint bs) ptr = unsafeUseAsCStringLen bs $ \(src, len) -> copyBytes ptr (castPtr src :: Ptr ()) len

_pokeValues :: [Attribute] -> Ptr () -> IO ()
_pokeValues [] p = return ()
_pokeValues (a:rem) p = do
  _pokeValue a p
  _pokeValues rem (p `plusPtr` _valueSize a)

_valuesSize :: [Attribute] -> Int
_valuesSize = foldr ((+) . _valueSize) 0

_makeLowLevelAttrs :: [Attribute] -> Ptr () -> [LlAttribute]
_makeLowLevelAttrs [] valuePtr = []
_makeLowLevelAttrs (a:rem) valuePtr =
  let valuePtr' = valuePtr `plusPtr` _valueSize a
      llAttr =
        LlAttribute
        {attributeType = _attrType a, attributeValuePtr = valuePtr, attributeSize = fromIntegral $ _valueSize a}
  in llAttr : _makeLowLevelAttrs rem valuePtr'

_withAttribs :: [Attribute] -> (Ptr LlAttribute -> IO a) -> IO a
_withAttribs attribs f =
  allocaBytes (_valuesSize attribs) $ \valuesPtr -> do
    _pokeValues attribs valuesPtr
    allocaArray (length attribs) $ \attrsPtr -> do
      pokeArray attrsPtr (_makeLowLevelAttrs attribs valuesPtr)
      f attrsPtr

_peekBigInt :: Ptr () -> CULong -> IO Integer
_peekBigInt ptr len = do
  arr <- peekArray (fromIntegral len) (castPtr ptr :: Ptr Word8)
  return $ foldl (\acc v -> fromIntegral v + (acc * 256)) 0 arr

_llAttrToAttr :: LlAttribute -> IO Attribute
_llAttrToAttr (LlAttribute ClassType ptr len) = do
  val <- peek (castPtr ptr :: Ptr CK_OBJECT_CLASS)
  return (Class $ toEnum $ fromIntegral val)
_llAttrToAttr (LlAttribute ModulusType ptr len) = do
  val <- _peekBigInt ptr len
  return (Modulus val)
_llAttrToAttr (LlAttribute PublicExponentType ptr len) = do
  val <- _peekBigInt ptr len
  return (PublicExponent val)
_llAttrToAttr (LlAttribute PrimeType ptr len) = do
  val <- _peekBigInt ptr len
  return (Prime val)
_llAttrToAttr (LlAttribute BaseType ptr len) = do
  val <- _peekBigInt ptr len
  return (Base val)
_llAttrToAttr (LlAttribute DecryptType ptr len) = do
  val <- peek (castPtr ptr :: Ptr CK_BBOOL)
  return $ Decrypt (val /= 0)
_llAttrToAttr (LlAttribute SignType ptr len) = do
  val <- peek (castPtr ptr :: Ptr CK_BBOOL)
  return $ Sign (val /= 0)
_llAttrToAttr (LlAttribute EcParamsType ptr len) = do
  val <- BS.packCStringLen (castPtr ptr, fromIntegral len)
  return $ EcParams val
_llAttrToAttr (LlAttribute EcdsaParamsType ptr len) = do
  val <- BS.packCStringLen (castPtr ptr, fromIntegral len)
  return $ EcdsaParams val
_llAttrToAttr (LlAttribute EcPointType ptr len) = do
  val <- BS.packCStringLen (castPtr ptr, fromIntegral len)
  return $ EcPoint val
_llAttrToAttr (LlAttribute typ _ _) = error ("_llAttrToAttr needs to be implemented for " ++ show typ)

_getAttr :: FunctionListPtr -> SessionHandle -> ObjectHandle -> AttributeType -> Ptr x -> IO ()
_getAttr functionListPtr sessionHandle objHandle attrType valPtr =
  alloca $ \attrPtr -> do
    poke attrPtr (LlAttribute attrType (castPtr valPtr) (fromIntegral $ sizeOf valPtr))
    rv <- getAttributeValue' functionListPtr sessionHandle objHandle attrPtr 1
    when (rv /= 0) $ fail $ "failed to get attribute: " ++ rvToStr rv

getObjectAttr' :: FunctionListPtr -> SessionHandle -> ObjectHandle -> AttributeType -> IO Attribute
getObjectAttr' functionListPtr sessionHandle objHandle attrType =
  alloca $ \attrPtr -> do
    poke attrPtr (LlAttribute attrType nullPtr 0)
    rv <- getAttributeValue' functionListPtr sessionHandle objHandle attrPtr 1
    attrWithLen <- peek attrPtr
    allocaBytes (fromIntegral $ attributeSize attrWithLen) $ \attrVal -> do
      poke attrPtr (LlAttribute attrType attrVal (attributeSize attrWithLen))
      rv <- getAttributeValue' functionListPtr sessionHandle objHandle attrPtr 1
      if rv /= 0
        then fail $ "failed to get attribute: " ++ rvToStr rv
        else do
          llAttr <- peek attrPtr
          _llAttrToAttr llAttr

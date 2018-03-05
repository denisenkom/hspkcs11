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


data Object =
  Object FunctionListPtr
         SessionHandle
         ObjectHandle
  deriving (Show)

-- | Represents an attribute of an object
data Attribute = Class ClassType -- ^ class of an object, e.g. 'PrivateKey', 'SecretKey'
    | KeyType KeyTypeValue -- ^ e.g. 'RSA' or 'AES'
    | Label String -- ^ object's label
    | Token Bool -- ^ whether object is stored on the token or is a temporary session object
    | Local Bool -- ^ whether key was generated on the token or not
    | Private Bool -- ^ whether object is a private object or not
    | Application String -- ^ can be used to specify an application that manages object
    | Decrypt Bool -- ^ allow/deny encryption function for an object
    | Sign Bool -- ^ allow/deny signing function for an object
    | Derive Bool -- ^ allow/deny key derivation functionality
    | SecondaryAuth Bool -- ^ if true secondary authentication would be required before key can be used
    | AlwaysAuthenticate Bool -- ^ if true user would have to supply PIN for each key use
    | ModulusBits CULong -- ^ number of bits used by modulus, for example in RSA public key
    | Modulus Integer -- ^ modulus value, used by RSA keys
    | PublicExponent Integer -- ^ value of public exponent, used by RSA public keys
    | PrimeBits CULong -- ^ number of bits used by prime in classic Diffie-Hellman
    | Prime Integer -- ^ value of prime modulus, used in classic Diffie-Hellman
    | Base Integer -- ^ value of generator, used in classic Diffie-Hellman
    | ValueLen CULong -- ^ length in bytes of the corresponding 'Value' attribute
    | Value BS.ByteString -- ^ object's value attribute, for example it is a DER encoded certificate for certificate objects
    | Extractable Bool -- ^ allows or denys extraction of certain attributes of private keys
    | NeverExtractable Bool -- ^ if true key never had been extractable
    | AlwaysSensitive Bool -- ^ if true key always had sensitive flag on
    | Modifiable Bool -- ^ allows or denys modification of object's attributes
    | EcParams BS.ByteString -- ^ DER encoded ANSI X9.62 parameters value for elliptic-curve algorithm
    | EcdsaParams BS.ByteString -- ^ DER encoded ANSI X9.62 parameters value for elliptic-curve algorithm
    | EcPoint BS.ByteString -- ^ DER encoded ANSI X9.62 point for elliptic-curve algorithm
    | CheckValue BS.ByteString -- ^ key checksum
    | KeyGenMechanism MechType -- ^ the mechanism used to generate the key
    deriving (Show, Eq)

data MarshalAttr = BoolAttr Bool
    | ClassTypeAttr ClassType
    | KeyTypeAttr KeyTypeValue
    | StringAttr String
    | BigIntAttr Integer
    | ULongAttr CULong
    | ByteStringAttr BS.ByteString


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
_attrType (Modifiable _) = ModifiableType
_attrType (Value _) = ValueType
_attrType (Prime _) = PrimeType
_attrType (Base _) = BaseType
_attrType (EcParams _) = EcParamsType
_attrType (EcPoint _) = EcPointType

_attrToMarshal :: Attribute -> MarshalAttr
_attrToMarshal (Class v) = ClassTypeAttr v
_attrToMarshal (KeyType v) = KeyTypeAttr v
_attrToMarshal (Label v) = StringAttr v
_attrToMarshal (ModulusBits v) = ULongAttr v
_attrToMarshal (PrimeBits v) = ULongAttr v
_attrToMarshal (ValueLen v) = ULongAttr v
_attrToMarshal (Token v) = BoolAttr v
_attrToMarshal (Extractable v) = BoolAttr v
_attrToMarshal (Modifiable v) = BoolAttr v
_attrToMarshal (Value v) = ByteStringAttr v
_attrToMarshal (Prime v) = BigIntAttr v
_attrToMarshal (Base v) = BigIntAttr v
_attrToMarshal (EcParams v) = ByteStringAttr v
_attrToMarshal (EcPoint v) = ByteStringAttr v

_valueSize :: MarshalAttr -> Int
_valueSize (ClassTypeAttr _) = sizeOf (0 :: CK_OBJECT_CLASS)
_valueSize (KeyTypeAttr _) = sizeOf (0 :: CK_KEY_TYPE)
_valueSize (StringAttr l) = BU8.length $ BU8.fromString l
_valueSize (ULongAttr _) = sizeOf (0 :: CULong)
_valueSize (BoolAttr _) = sizeOf (0 :: CK_BBOOL)
_valueSize (ByteStringAttr bs) = BS.length bs
_valueSize (BigIntAttr p) = _bigIntLen p

_pokeValue :: MarshalAttr -> Ptr () -> IO ()
_pokeValue (ClassTypeAttr c) ptr = poke (castPtr ptr :: Ptr CK_OBJECT_CLASS) (fromIntegral $ fromEnum c)
_pokeValue (KeyTypeAttr k) ptr = poke (castPtr ptr :: Ptr CK_KEY_TYPE) (fromIntegral $ fromEnum k)
_pokeValue (StringAttr s) ptr =
  unsafeUseAsCStringLen (BU8.fromString s) $ \(src, len) -> copyBytes ptr (castPtr src :: Ptr ()) len
_pokeValue (ULongAttr l) ptr = poke (castPtr ptr :: Ptr CULong) (fromIntegral l)
_pokeValue (BoolAttr b) ptr = poke (castPtr ptr :: Ptr CK_BBOOL) (fromBool b :: CK_BBOOL)
_pokeValue (ByteStringAttr bs) ptr = unsafeUseAsCStringLen bs $ \(src, len) -> copyBytes ptr (castPtr src :: Ptr ()) len
_pokeValue (BigIntAttr p) ptr = _pokeBigInt p (castPtr ptr)

_pokeValues :: [Attribute] -> Ptr () -> IO ()
_pokeValues [] p = return ()
_pokeValues (a:rem) p = do
  _pokeValue (_attrToMarshal a) p
  _pokeValues rem (p `plusPtr` _valueSize (_attrToMarshal a))

_valuesSize :: [Attribute] -> Int
_valuesSize = foldr ((+) . (_valueSize . _attrToMarshal)) 0

_makeLowLevelAttrs :: [Attribute] -> Ptr () -> [LlAttribute]
_makeLowLevelAttrs [] valuePtr = []
_makeLowLevelAttrs (a:rem) valuePtr =
  let valuePtr' = valuePtr `plusPtr` _valueSize (_attrToMarshal a)
      llAttr =
        LlAttribute
        {attributeType = _attrType a, attributeValuePtr = valuePtr, attributeSize = fromIntegral $ _valueSize (_attrToMarshal a)}
  in llAttr : _makeLowLevelAttrs rem valuePtr'

_withAttribs :: [Attribute] -> (Ptr LlAttribute -> IO a) -> IO a
_withAttribs attribs f =
  allocaBytes (_valuesSize attribs) $ \valuesPtr -> do
    _pokeValues attribs valuesPtr
    allocaArray (length attribs) $ \attrsPtr -> do
      pokeArray attrsPtr (_makeLowLevelAttrs attribs valuesPtr)
      f attrsPtr

_peekBigInt ptr len constr = do
  arr <- peekArray (fromIntegral len) (castPtr ptr :: Ptr Word8)
  return $ constr $ foldl (\acc v -> fromIntegral v + (acc * 256)) 0 arr

_peekBool ptr len constr = do
  val <- peek (castPtr ptr :: Ptr CK_BBOOL)
  return $ constr (val /= 0)

_peekByteString ptr len constr = do
  val <- BS.packCStringLen (castPtr ptr, fromIntegral len)
  return $ constr val

_peekU2F8String :: Ptr () -> CULong -> (String -> Attribute) -> IO Attribute
_peekU2F8String ptr len constr = do
  val <- BS.packCStringLen (castPtr ptr, fromIntegral len)
  return $ constr $ BU8.toString val

_llAttrToAttr :: LlAttribute -> IO Attribute
_llAttrToAttr (LlAttribute ClassType ptr len) = do
  val <- peek (castPtr ptr :: Ptr CK_OBJECT_CLASS)
  return (Class $ toEnum $ fromIntegral val)
_llAttrToAttr (LlAttribute KeyTypeType ptr len) = do
  val <- peek (castPtr ptr :: Ptr CK_KEY_TYPE)
  return (KeyType $ toEnum $ fromIntegral val)
_llAttrToAttr (LlAttribute KeyGenMechanismType ptr len) = do
  val <- peek (castPtr ptr :: Ptr CK_MECHANISM_TYPE)
  return (KeyGenMechanism $ toEnum $ fromIntegral val)
_llAttrToAttr (LlAttribute PrivateType ptr len) = _peekBool ptr len Private
_llAttrToAttr (LlAttribute ModulusType ptr len) = _peekBigInt ptr len Modulus
_llAttrToAttr (LlAttribute PublicExponentType ptr len) = _peekBigInt ptr len PublicExponent
_llAttrToAttr (LlAttribute PrimeType ptr len) = _peekBigInt ptr len Prime
_llAttrToAttr (LlAttribute BaseType ptr len) = _peekBigInt ptr len Base
_llAttrToAttr (LlAttribute DecryptType ptr len) = _peekBool ptr len Decrypt
_llAttrToAttr (LlAttribute SignType ptr len) = _peekBool ptr len Sign
_llAttrToAttr (LlAttribute ExtractableType ptr len) = _peekBool ptr len Sign
_llAttrToAttr (LlAttribute ModifiableType ptr len) = _peekBool ptr len Modifiable
_llAttrToAttr (LlAttribute EcParamsType ptr len) = _peekByteString ptr len EcParams
_llAttrToAttr (LlAttribute EcdsaParamsType ptr len) = _peekByteString ptr len EcdsaParams
_llAttrToAttr (LlAttribute EcPointType ptr len) = _peekByteString ptr len EcPoint
_llAttrToAttr (LlAttribute LabelType ptr len) = _peekU2F8String ptr len Label
_llAttrToAttr (LlAttribute ApplicationType ptr len) = _peekU2F8String ptr len Application
_llAttrToAttr (LlAttribute ValueType ptr len) = _peekByteString ptr len Value
_llAttrToAttr (LlAttribute CheckValueType ptr len) = _peekByteString ptr len CheckValue
_llAttrToAttr (LlAttribute DeriveType ptr len) = _peekBool ptr len Derive
_llAttrToAttr (LlAttribute LocalType ptr len) = _peekBool ptr len Local
_llAttrToAttr (LlAttribute NeverExtractableType ptr len) = _peekBool ptr len NeverExtractable
_llAttrToAttr (LlAttribute AlwaysSensitiveType ptr len) = _peekBool ptr len AlwaysSensitive
_llAttrToAttr (LlAttribute SecondaryAuthType ptr len) = _peekBool ptr len SecondaryAuth
_llAttrToAttr (LlAttribute AlwaysAuthenticateType ptr len) = _peekBool ptr len AlwaysAuthenticate
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

getBoolAttr :: AttributeType -> Object -> IO Bool
getBoolAttr attrType (Object funcListPtr sessHandle objHandle) =
  alloca $ \valuePtr -> do
    _getAttr funcListPtr sessHandle objHandle attrType (valuePtr :: Ptr CK_BBOOL)
    val <- peek valuePtr
    return $ toBool val

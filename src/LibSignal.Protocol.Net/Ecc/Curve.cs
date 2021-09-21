namespace LibSignal.Protocol.Net.Ecc
{
    public class Curve
    {

        public static readonly int DJB_TYPE = 0x05;

        public static bool isNative()
        {
            return Curve25519.getInstance(BEST).isNative();
        }

        public static ECKeyPair generateKeyPair()
        {
            Curve25519KeyPair keyPair = Curve25519.getInstance(BEST).generateKeyPair();

            return new ECKeyPair(new DjbECPublicKey(keyPair.getPublicKey()), new DjbECPrivateKey(keyPair.getPrivateKey()));
        }

        // throws InvalidKeyException
        public static ECPublicKey decodePoint(byte[] bytes, int offset)
        {
            if (bytes == null || bytes.Length - offset < 1)
            {
                throw new InvalidKeyException("No key type identifier");
            }

            int type = bytes[offset] & 0xFF;

            switch (type)
            {
                case Curve.DJB_TYPE:
                    if (bytes.Length - offset < 33)
                    {
                        throw new InvalidKeyException("Bad key length: " + bytes.Length);
                    }

                    byte[] keyBytes = new byte[32];
                    System.arraycopy(bytes, offset + 1, keyBytes, 0, keyBytes.Length);
                    return new DjbECPublicKey(keyBytes);
                default:
                    throw new InvalidKeyException("Bad key type: " + type);
            }
        }

        public static ECPrivateKey decodePrivatePoint(byte[] bytes)
        {
            return new DjbECPrivateKey(bytes);
        }

        //Throws InvalidKeyException
        public static byte[] calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)
        {
            if (publicKey == null)
            {
                throw new InvalidKeyException("public value is null");
            }

            if (privateKey == null)
            {
                throw new InvalidKeyException("private value is null");
            }

            if (publicKey.getType() != privateKey.getType())
            {
                throw new InvalidKeyException("Public and private keys must be of the same type!");
            }

            if (publicKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(BEST).calculateAgreement(((DjbECPublicKey)publicKey).getPublicKey(), ((DjbECPrivateKey)privateKey).getPrivateKey());
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + publicKey.getType());
            }
        }

        //Throws InvalidKeyException
        public static bool verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
        {
            if (signingKey == null || message == null || signature == null)
            {
                throw new InvalidKeyException("Values must not be null");
            }

            if (signingKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(BEST).verifySignature(((DjbECPublicKey)signingKey).getPublicKey(), message, signature);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.getType());
            }
        }

        //Throws InvalidKeyException
        public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
        {
            if (signingKey == null || message == null)
            {
                throw new InvalidKeyException("Values must not be null");
            }

            if (signingKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(BEST).calculateSignature(((DjbECPrivateKey)signingKey).getPrivateKey(), message);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.getType());
            }
        }

        //Throws InvalidKeyException
        public static byte[] calculateVrfSignature(ECPrivateKey signingKey, byte[] message)
        {
            if (signingKey == null || message == null)
            {
                throw new InvalidKeyException("Values must not be null");
            }

            if (signingKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(BEST).calculateVrfSignature(((DjbECPrivateKey)signingKey).getPrivateKey(), message);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.getType());
            }
        }

        //Throws InvalidKeyException, VrfSignatureVerificationFailedException
        public static byte[] verifyVrfSignature(ECPublicKey signingKey, byte[] message, byte[] signature)
        {
            if (signingKey == null || message == null || signature == null)
            {
                throw new InvalidKeyException("Values must not be null");
            }

            if (signingKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(BEST).verifyVrfSignature(((DjbECPublicKey)signingKey).getPublicKey(), message, signature);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.getType());
            }
        }

    }
}

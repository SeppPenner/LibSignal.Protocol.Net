namespace LibSignal.Protocol.Net
{
    using LibSignal.Protocol.Net.Ecc;
    using LibSignal.Protocol.Net.Util;


    public class IdentityKey
    {

        private readonly ECPublicKey publicKey;

        public IdentityKey(ECPublicKey publicKey)
        {
            this.publicKey = publicKey;
        }

        // Throws InvalidKeyException
        public IdentityKey(byte[] bytes, int offset)
        {
            this.publicKey = Curve.decodePoint(bytes, offset);
        }

        public ECPublicKey getPublicKey()
        {
            return publicKey;
        }

        public byte[] serialize()
        {
            return publicKey.serialize();
        }

        public string getFingerprint()
        {
            return Hex.toString(publicKey.serialize());
        }

        public override bool equals(object other)
        {
            if (other == null) return false;
            if (!(other instanceof IdentityKey)) return false;

            return publicKey.equals(((IdentityKey)other).getPublicKey());
        }

        public override int hashCode()
        {
            return publicKey.hashCode();
        }
    }

}


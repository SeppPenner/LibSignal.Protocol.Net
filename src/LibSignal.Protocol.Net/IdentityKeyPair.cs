namespace LibSignal.Protocol.Net
{
    using LibSignal.Protocol.Net.Ecc;


    public class IdentityKeyPair
    {

        private readonly IdentityKey publicKey;

        private readonly ECPrivateKey privateKey;

        public IdentityKeyPair(IdentityKey publicKey, ECPrivateKey privateKey)
        {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        // Throws InvalidKeyException
        public IdentityKeyPair(byte[] serialized)
        {
            try
            {
                IdentityKeyPairStructure structure = IdentityKeyPairStructure.parseFrom(serialized);
                this.publicKey = new IdentityKey(structure.getPublicKey().toByteArray(), 0);
                this.privateKey = Curve.decodePrivatePoint(structure.getPrivateKey().toByteArray());
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidKeyException(e);
            }
        }

        public IdentityKey getPublicKey()
        {
            return publicKey;
        }

        public ECPrivateKey getPrivateKey()
        {
            return privateKey;
        }

        public byte[] serialize()
        {
            return IdentityKeyPairStructure.newBuilder().setPublicKey(ByteString.copyFrom(publicKey.serialize())).setPrivateKey(ByteString.copyFrom(privateKey.serialize())).build().toByteArray();
        }
    }

}
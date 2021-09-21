namespace LibSignal.Protocol.Net.State
{
    using LibSignal.Protocol.Net.Ecc;


    public class SignedPreKeyRecord
    {

        private SignedPreKeyRecordStructure structure;

        public SignedPreKeyRecord(int id, long timestamp, ECKeyPair keyPair, byte[] signature)
        {
            this.structure = SignedPreKeyRecordStructure.newBuilder().setId(id).setPublicKey(ByteString.copyFrom(keyPair.getPublicKey().serialize())).setPrivateKey(ByteString.copyFrom(keyPair.getPrivateKey().serialize()))
                .setSignature(ByteString.copyFrom(signature)).setTimestamp(timestamp).build();
        }

        // Throws IOException
        public SignedPreKeyRecord(byte[] serialized)
        {
            this.structure = SignedPreKeyRecordStructure.parseFrom(serialized);
        }

        public int getId()
        {
            return this.structure.getId();
        }

        public long getTimestamp()
        {
            return this.structure.getTimestamp();
        }

        public ECKeyPair getKeyPair()
        {
            try
            {
                var publicKey = Curve.decodePoint(this.structure.getPublicKey().toByteArray(), 0);
                var privateKey = Curve.decodePrivatePoint(this.structure.getPrivateKey().toByteArray());

                return new ECKeyPair(publicKey, privateKey);
            }
            catch (InvalidKeyException e)
            {
                throw new AssertionError(e);
            }
        }

        public byte[] getSignature()
        {
            return this.structure.getSignature().toByteArray();
        }

        public byte[] serialize()
        {
            return this.structure.toByteArray();
        }
    }
}
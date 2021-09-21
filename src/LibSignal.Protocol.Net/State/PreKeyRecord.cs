namespace LibSignal.Protocol.Net.State
{
    using LibSignal.Protocol.Net.Ecc;


    public class PreKeyRecord
    {

        private PreKeyRecordStructure structure;

        public PreKeyRecord(int id, ECKeyPair keyPair)
        {
            this.structure = PreKeyRecordStructure.newBuilder().setId(id).setPublicKey(ByteString.copyFrom(keyPair.getPublicKey().serialize())).setPrivateKey(ByteString.copyFrom(keyPair.getPrivateKey().serialize())).build();
        }

        //Throws IOException
        public PreKeyRecord(byte[] serialized)
        {
            this.structure = PreKeyRecordStructure.parseFrom(serialized);
        }

        public int getId()
        {
            return this.structure.getId();
        }

        public ECKeyPair getKeyPair()
        {
            try
            {
                ECPublicKey publicKey = Curve.decodePoint(this.structure.getPublicKey().toByteArray(), 0);
                ECPrivateKey privateKey = Curve.decodePrivatePoint(this.structure.getPrivateKey().toByteArray());

                return new ECKeyPair(publicKey, privateKey);
            }
            catch (InvalidKeyException e)
            {
                throw new AssertionError(e);
            }
        }

        public byte[] serialize()
        {
            return this.structure.toByteArray();
        }
    }
}
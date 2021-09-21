namespace LibSignal.Protocol.Net.Ecc
{
    public class DjbECPrivateKey : ECPrivateKey
    {

        private readonly byte[] privateKey;

        DjbECPrivateKey(byte[] privateKey)
        {
            this.privateKey = privateKey;
        }


        public override byte[] serialize()
        {
            return privateKey;
        }

        public override int getType()
        {
            return Curve.DJB_TYPE;
        }

        public byte[] getPrivateKey()
        {
            return privateKey;
        }
    }
}
namespace LibSignal.Protocol.Net.Ecc
{
    public class ECKeyPair
    {

        private readonly ECPublicKey publicKey;
        private readonly ECPrivateKey privateKey;

        public ECKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey)
        {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public ECPublicKey getPublicKey()
        {
            return publicKey;
        }

        public ECPrivateKey getPrivateKey()
        {
            return privateKey;
        }
    }
}

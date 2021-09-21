namespace LibSignal.Protocol.Net.Ratchet
{
    public class MessageKeys
    {
        private readonly SecretKeySpec   cipherKey;
        private readonly SecretKeySpec   macKey;
        private readonly IvParameterSpec iv;
        private readonly int counter;

        public MessageKeys(SecretKeySpec cipherKey, SecretKeySpec macKey, IvParameterSpec iv, int counter)
        {
            this.cipherKey = cipherKey;
            this.macKey = macKey;
            this.iv = iv;
            this.counter = counter;
        }

        public SecretKeySpec getCipherKey()
        {
            return cipherKey;
        }

        public SecretKeySpec getMacKey()
        {
            return macKey;
        }

        public IvParameterSpec getIv()
        {
            return iv;
        }

        public int getCounter()
        {
            return counter;
        }
    }
}
namespace LibSignal.Protocol.Net.Groups.Ratchet
{
    public class SenderChainKey
    {

        private static readonly byte[] MESSAGE_KEY_SEED = { 0x01 };
        private static readonly byte[] CHAIN_KEY_SEED = { 0x02 };

        private readonly int iteration;
        private readonly byte[] chainKey;

        public SenderChainKey(int iteration, byte[] chainKey)
        {
            this.iteration = iteration;
            this.chainKey = chainKey;
        }

        public int getIteration()
        {
            return iteration;
        }

        public SenderMessageKey getSenderMessageKey()
        {
            return new SenderMessageKey(iteration, getDerivative(MESSAGE_KEY_SEED, chainKey));
        }

        public SenderChainKey getNext()
        {
            return new SenderChainKey(iteration + 1, getDerivative(CHAIN_KEY_SEED, chainKey));
        }

        public byte[] getSeed()
        {
            return chainKey;
        }

        private byte[] getDerivative(byte[] seed, byte[] key)
        {
            try
            {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(key, "HmacSHA256"));

                return mac.doFinal(seed);
            }
            catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new AssertionError(e);
            }
        }

    }
}
namespace LibSignal.Protocol.Net.Groups.Ratchet
{
    using LibSignal.Protocol.Net.Kdf;
    using LibSignal.Protocol.Net.Util;


    public class SenderMessageKey
    {

        private readonly int iteration;
        private readonly byte[] iv;
        private readonly byte[] cipherKey;
        private readonly byte[] seed;

        public SenderMessageKey(int iteration, byte[] seed)
        {
            byte[] derivative = new HKDFv3().deriveSecrets(seed, "WhisperGroup".getBytes(), 48);
            var parts = ByteUtil.split(derivative, 16, 32);

            this.iteration = iteration;
            this.seed = seed;
            this.iv = parts[0];
            this.cipherKey = parts[1];
        }

        public int getIteration()
        {
            return iteration;
        }

        public byte[] getIv()
        {
            return iv;
        }

        public byte[] getCipherKey()
        {
            return cipherKey;
        }

        public byte[] getSeed()
        {
            return seed;
        }
    }

}
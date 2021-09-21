namespace LibSignal.Protocol.Net.Kdf
{
    using LibSignal.Protocol.Net.Util;


    public class DerivedRootSecrets
    {

        public static readonly int SIZE = 64;

        private readonly byte[] rootKey;
        private readonly byte[] chainKey;

        public DerivedRootSecrets(byte[] okm)
        {
            byte[][] keys = ByteUtil.split(okm, 32, 32);
            this.rootKey = keys[0];
            this.chainKey = keys[1];
        }

        public byte[] getRootKey()
        {
            return rootKey;
        }

        public byte[] getChainKey()
        {
            return chainKey;
        }

    }

}


namespace LibSignal.Protocol.Net.Kdf
{
    using LibSignal.Protocol.Net.Util;
    public class DerivedMessageSecrets
    {

        public static readonly int SIZE = 80;
        private static readonly int CIPHER_KEY_LENGTH = 32;
        private static readonly int MAC_KEY_LENGTH = 32;
        private static readonly int IV_LENGTH = 16;

        private readonly SecretKeySpec cipherKey;
        private readonly SecretKeySpec macKey;
        private readonly IvParameterSpec iv;

        public DerivedMessageSecrets(byte[] okm)
        {
            try
            {
                byte[][] keys = ByteUtil.split(okm, CIPHER_KEY_LENGTH, MAC_KEY_LENGTH, IV_LENGTH);

                this.cipherKey = new SecretKeySpec(keys[0], "AES");
                this.macKey = new SecretKeySpec(keys[1], "HmacSHA256");
                this.iv = new IvParameterSpec(keys[2]);
            }
            catch (ParseException e)
            {
                throw new AssertionError(e);
            }
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
    }
}
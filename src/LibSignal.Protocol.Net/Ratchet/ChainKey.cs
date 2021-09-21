namespace LibSignal.Protocol.Net.Ratchet
{
    using LibSignal.Protocol.Net.Kdf;


    public class ChainKey
    {

        private static readonly byte[] MESSAGE_KEY_SEED = { 0x01 };
        private static readonly byte[] CHAIN_KEY_SEED = { 0x02 };

        private readonly HKDF   kdf;
        private readonly byte[] key;
        private readonly int index;

        public ChainKey(HKDF kdf, byte[] key, int index)
        {
            this.kdf = kdf;
            this.key = key;
            this.index = index;
        }

        public byte[] getKey()
        {
            return key;
        }

        public int getIndex()
        {
            return index;
        }

        public ChainKey getNextChainKey()
        {
            byte[] nextKey = getBaseMaterial(CHAIN_KEY_SEED);
            return new ChainKey(kdf, nextKey, index + 1);
        }

        public MessageKeys getMessageKeys()
        {
            byte[] inputKeyMaterial = getBaseMaterial(MESSAGE_KEY_SEED);
            byte[] keyMaterialBytes = kdf.deriveSecrets(inputKeyMaterial, "WhisperMessageKeys".getBytes(), DerivedMessageSecrets.SIZE);
            DerivedMessageSecrets keyMaterial = new DerivedMessageSecrets(keyMaterialBytes);

            return new MessageKeys(keyMaterial.getCipherKey(), keyMaterial.getMacKey(), keyMaterial.getIv(), index);
        }

        private byte[] getBaseMaterial(byte[] seed)
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


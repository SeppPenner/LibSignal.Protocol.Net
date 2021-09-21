namespace LibSignal.Protocol.Net.Ratchet
{
    using LibSignal.Protocol.Net.Ecc;
    using LibSignal.Protocol.Net.Kdf;
    using LibSignal.Protocol.Net.Util;


    public class RootKey
    {

        private readonly HKDF kdf;

        private readonly byte[] key;

        public RootKey(HKDF kdf, byte[] key)
        {
            this.kdf = kdf;
            this.key = key;
        }

        public byte[] getKeyBytes()
        {
            return key;
        }

        // Throws InvalidKeyException
        public Pair<RootKey, ChainKey> createChain(ECPublicKey theirRatchetKey, ECKeyPair ourRatchetKey)
        {
            byte[] sharedSecret = Curve.calculateAgreement(theirRatchetKey, ourRatchetKey.getPrivateKey());
            byte[] derivedSecretBytes = kdf.deriveSecrets(sharedSecret, key, "WhisperRatchet".getBytes(), DerivedRootSecrets.SIZE);
            DerivedRootSecrets derivedSecrets = new DerivedRootSecrets(derivedSecretBytes);

            RootKey newRootKey = new RootKey(kdf, derivedSecrets.getRootKey());
            ChainKey newChainKey = new ChainKey(kdf, derivedSecrets.getChainKey(), 0);

            return new Pair<>(newRootKey, newChainKey);
        }
    }
}
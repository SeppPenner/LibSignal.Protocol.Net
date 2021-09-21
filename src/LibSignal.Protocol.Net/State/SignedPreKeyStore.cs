namespace LibSignal.Protocol.Net.State
{
    using System.Collections.Generic;


    public interface SignedPreKeyStore
    {
        // Throws InvalidKeyIdException
        public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId);

        public List<SignedPreKeyRecord> loadSignedPreKeys();

        public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record);


        public bool containsSignedPreKey(int signedPreKeyId);


        public void removeSignedPreKey(int signedPreKeyId);

    }
}

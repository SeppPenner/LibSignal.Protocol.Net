namespace LibSignal.Protocol.Net.State
{
    public interface PreKeyStore
    {

        // Throws InvalidKeyIdException
        public PreKeyRecord loadPreKey(int preKeyId);

        public void storePreKey(int preKeyId, PreKeyRecord record);


        public bool containsPreKey(int preKeyId);

        public void removePreKey(int preKeyId);

    }
}
namespace LibSignal.Protocol.Net.State.Implementation
{
    using System.IO;


    public class InMemoryPreKeyStore : PreKeyStore
    {

        private readonly Map<int, byte[]> store = new HashMap<>();

        // Throws InvalidKeyIdException
        public override PreKeyRecord loadPreKey(int preKeyId)
        {
            try
            {
                if (!store.containsKey(preKeyId))
                {
                    throw new InvalidKeyIdException("No such prekeyrecord!");
                }

                return new PreKeyRecord(store.get(preKeyId));
            }
            catch (IOException e)
            {
                throw new AssertionError(e);
            }
        }

        public override void storePreKey(int preKeyId, PreKeyRecord record)
        {
            store.put(preKeyId, record.serialize());
        }

        public override bool containsPreKey(int preKeyId)
        {
            return store.containsKey(preKeyId);
        }

        public override void removePreKey(int preKeyId)
        {
            store.remove(preKeyId);
        }
    }
}
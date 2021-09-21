namespace LibSignal.Protocol.Net.State.Implementation
{
    using System.Collections.Generic;
    using System.IO;


    public class InMemorySignedPreKeyStore : SignedPreKeyStore
    {

        private readonly Map<int, byte[]> store = new HashMap<>();

        // Throws InvalidKeyIdException
        public override SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId)
        {
            try
            {
                if (!store.containsKey(signedPreKeyId))
                {
                    throw new InvalidKeyIdException("No such signedprekeyrecord! " + signedPreKeyId);
                }

                return new SignedPreKeyRecord(store.get(signedPreKeyId));
            }
            catch (IOException e)
            {
                throw new AssertionError(e);
            }
        }

        public override List<SignedPreKeyRecord> loadSignedPreKeys()
        {
            try
            {
                List<SignedPreKeyRecord> results = new LinkedList<>();

                foreach (byte[] serialized in store.values())
                {
                    results.Add(new SignedPreKeyRecord(serialized));
                }

                return results;
            }
            catch (IOException e)
            {
                throw new AssertionError(e);
            }
        }

        public override void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record)
        {
            store.put(signedPreKeyId, record.serialize());
        }

        public override bool containsSignedPreKey(int signedPreKeyId)
        {
            return store.containsKey(signedPreKeyId);
        }

        public override void removeSignedPreKey(int signedPreKeyId)
        {
            store.remove(signedPreKeyId);
        }
    }

}


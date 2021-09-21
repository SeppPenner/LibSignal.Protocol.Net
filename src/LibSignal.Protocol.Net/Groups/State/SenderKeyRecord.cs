namespace LibSignal.Protocol.Net.Groups.State
{
    using System.Collections.Generic;

    using LibSignal.Protocol.Net.Ecc;


    public class SenderKeyRecord
    {

        private static readonly int MAX_STATES = 5;

        private LinkedList<SenderKeyState> senderKeyStates = new LinkedList<>();

        public SenderKeyRecord() {}

        // throws IOException
        public SenderKeyRecord(byte[] serialized)
        {
            SenderKeyRecordStructure senderKeyRecordStructure = SenderKeyRecordStructure.parseFrom(serialized);

            foreach (StorageProtos.SenderKeyStateStructure structure in senderKeyRecordStructure.getSenderKeyStatesList())
            {
                this.senderKeyStates.add(new SenderKeyState(structure));
            }
        }

        public bool isEmpty()
        {
            return senderKeyStates.isEmpty();
        }

        // throws InvalidKeyIdException
        public SenderKeyState getSenderKeyState()
        {
            if (!senderKeyStates.isEmpty())
            {
                return senderKeyStates.get(0);
            }
            else
            {
                throw new InvalidKeyIdException("No key state in record!");
            }
        }

        // throws InvalidKeyIdException
        public SenderKeyState getSenderKeyState(int keyId)
        {
            foreach (SenderKeyState state in senderKeyStates)
            {
                if (state.getKeyId() == keyId)
                {
                    return state;
                }
            }

            throw new InvalidKeyIdException("No keys for: " + keyId);
        }

        public void addSenderKeyState(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey)
        {
            senderKeyStates.addFirst(new SenderKeyState(id, iteration, chainKey, signatureKey));

            if (senderKeyStates.size() > MAX_STATES)
            {
                senderKeyStates.removeLast();
            }
        }

        public void setSenderKeyState(int id, int iteration, byte[] chainKey, ECKeyPair signatureKey)
        {
            senderKeyStates.Clear();
            senderKeyStates.Add(new SenderKeyState(id, iteration, chainKey, signatureKey));
        }

        public byte[] serialize()
        {
            SenderKeyRecordStructure.Builder recordStructure = SenderKeyRecordStructure.newBuilder();

            foreach (SenderKeyState senderKeyState in senderKeyStates) {
                recordStructure.addSenderKeyStates(senderKeyState.getStructure());
            }

            return recordStructure.build().toByteArray();
        }
    }

}

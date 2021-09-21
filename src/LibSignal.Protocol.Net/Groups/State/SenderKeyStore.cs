namespace LibSignal.Protocol.Net.Groups.State
{
    public interface SenderKeyStore
    {
        public void storeSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record);

        public SenderKeyRecord loadSenderKey(SenderKeyName senderKeyName);
    }
}
namespace LibSignal.Protocol.Net.Protocol
{
    public interface CiphertextMessage
    {

        public static readonly int CURRENT_VERSION = 3;

        public static readonly int WHISPER_TYPE = 2;
        public static readonly int PREKEY_TYPE = 3;
        public static readonly int SENDERKEY_TYPE = 4;
        public static readonly int SENDERKEY_DISTRIBUTION_TYPE = 5;

        // This should be the worst case (worse than V2).  So not always accurate, but good enough for padding.
        public static readonly int ENCRYPTED_MESSAGE_OVERHEAD = 53;

        public byte[] serialize();
        public int getType();

    }
}

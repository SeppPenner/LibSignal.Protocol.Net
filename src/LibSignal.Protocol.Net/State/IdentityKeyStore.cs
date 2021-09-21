namespace LibSignal.Protocol.Net.State
{
    public interface IdentityKeyStore
    {
        public enum Direction
        {
            SENDING, RECEIVING
        }
        public IdentityKeyPair getIdentityKeyPair();

        public int getLocalRegistrationId();

        public bool saveIdentity(SignalProtocolAddress address, IdentityKey identityKey);


        public bool isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction);


        public IdentityKey getIdentity(SignalProtocolAddress address);

    }
}

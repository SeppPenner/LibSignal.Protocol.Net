namespace LibSignal.Protocol.Net.State.Implementation
{
    public class InMemoryIdentityKeyStore : IdentityKeyStore
    {

        private readonly Map<SignalProtocolAddress, IdentityKey> trustedKeys = new HashMap<>();

        private readonly IdentityKeyPair identityKeyPair;
        private readonly int localRegistrationId;

        public InMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair, int localRegistrationId)
        {
            this.identityKeyPair = identityKeyPair;
            this.localRegistrationId = localRegistrationId;
        }

        public override IdentityKeyPair getIdentityKeyPair()
        {
            return identityKeyPair;
        }

        public override int getLocalRegistrationId()
        {
            return localRegistrationId;
        }

        public override bool saveIdentity(SignalProtocolAddress address, IdentityKey identityKey)
        {
            IdentityKey existing = trustedKeys.get(address);

            if (!identityKey.Equals(existing))
            {
                trustedKeys.put(address, identityKey);
                return true;
            }
            else
            {
                return false;
            }
        }

        public override bool isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, IdentityKeyStore.Direction direction)
        {
            IdentityKey trusted = trustedKeys.get(address);
            return (trusted == null || trusted.Equals(identityKey));
        }

        public override IdentityKey getIdentity(SignalProtocolAddress address)
        {
            return trustedKeys.get(address);
        }
    }

}


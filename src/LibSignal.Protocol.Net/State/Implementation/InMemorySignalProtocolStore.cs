namespace LibSignal.Protocol.Net.State.Implementation
{
    using System;
    using System.Collections.Generic;

    public class InMemorySignalProtocolStore : SignalProtocolStore
    {

        private readonly InMemoryPreKeyStore preKeyStore = new InMemoryPreKeyStore();

        private readonly InMemorySessionStore sessionStore = new InMemorySessionStore();

        private readonly InMemorySignedPreKeyStore signedPreKeyStore = new InMemorySignedPreKeyStore();

        private readonly InMemoryIdentityKeyStore identityKeyStore;

        public InMemorySignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId)
        {
            this.identityKeyStore = new InMemoryIdentityKeyStore(identityKeyPair, registrationId);
        }

        public override IdentityKeyPair getIdentityKeyPair()
        {
            return identityKeyStore.getIdentityKeyPair();
        }

        public override int getLocalRegistrationId()
        {
            return identityKeyStore.getLocalRegistrationId();
        }

        public override bool saveIdentity(SignalProtocolAddress address, IdentityKey identityKey)
        {
            return identityKeyStore.saveIdentity(address, identityKey);
        }

        public override bool isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, IdentityKeyStore.Direction direction)
        {
            return identityKeyStore.isTrustedIdentity(address, identityKey, direction);
        }

        public override IdentityKey getIdentity(SignalProtocolAddress address)
        {
            return identityKeyStore.getIdentity(address);
        }

        // Throws InvalidKeyIdException
        public override PreKeyRecord loadPreKey(int preKeyId)
        {
            return preKeyStore.loadPreKey(preKeyId);
        }

        public override void storePreKey(int preKeyId, PreKeyRecord record)
        {
            preKeyStore.storePreKey(preKeyId, record);
        }

        public override bool containsPreKey(int preKeyId)
        {
            return preKeyStore.containsPreKey(preKeyId);
        }

        public override void removePreKey(int preKeyId)
        {
            preKeyStore.removePreKey(preKeyId);
        }

        public override SessionRecord loadSession(SignalProtocolAddress address)
        {
            return sessionStore.loadSession(address);
        }

        public override List<int> getSubDeviceSessions(String name)
        {
            return sessionStore.getSubDeviceSessions(name);
        }

        public override void storeSession(SignalProtocolAddress address, SessionRecord record)
        {
            sessionStore.storeSession(address, record);
        }

        public override bool containsSession(SignalProtocolAddress address)
        {
            return sessionStore.containsSession(address);
        }

        public override void deleteSession(SignalProtocolAddress address)
        {
            sessionStore.deleteSession(address);
        }

        public override void deleteAllSessions(string name)
        {
            sessionStore.deleteAllSessions(name);
        }

        // Throws InvalidKeyIdException
        public override SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId)
        {
            return signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
        }

        public override List<SignedPreKeyRecord> loadSignedPreKeys()
        {
            return signedPreKeyStore.loadSignedPreKeys();
        }

        public override void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record)
        {
            signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
        }

        public override bool containsSignedPreKey(int signedPreKeyId)
        {
            return signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
        }

        public override void removeSignedPreKey(int signedPreKeyId)
        {
            signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
        }
    }

}


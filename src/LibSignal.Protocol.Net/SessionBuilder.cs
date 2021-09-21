
namespace LibSignal.Protocol.Net
{
    using LibSignal.Protocol.Net.Ecc;
    using LibSignal.Protocol.Net.Logging;
    using LibSignal.Protocol.Net.Protocol;
    using LibSignal.Protocol.Net.Ratchet;
    using LibSignal.Protocol.Net.State;
    using LibSignal.Protocol.Net.Util.Guava;


    public class SessionBuilder
    {

        private static readonly string TAG = SessionBuilder.class.getSimpleName();

        private readonly SessionStore sessionStore;

        private readonly PreKeyStore preKeyStore;

        private readonly SignedPreKeyStore signedPreKeyStore;

        private readonly IdentityKeyStore identityKeyStore;

        private readonly SignalProtocolAddress remoteAddress;

        public SessionBuilder(SessionStore sessionStore, PreKeyStore preKeyStore, SignedPreKeyStore signedPreKeyStore, IdentityKeyStore identityKeyStore, SignalProtocolAddress remoteAddress)
        {
            this.sessionStore = sessionStore;
            this.preKeyStore = preKeyStore;
            this.signedPreKeyStore = signedPreKeyStore;
            this.identityKeyStore = identityKeyStore;
            this.remoteAddress = remoteAddress;
        }


        public SessionBuilder(SignalProtocolStore store, SignalProtocolAddress remoteAddress)
        {
            this(store, store, store, store, remoteAddress);
        }

        // throws InvalidKeyIdException, InvalidKeyException, UntrustedIdentityException
        Optional<int> process(SessionRecord sessionRecord, PreKeySignalMessage message)

        

        {
            IdentityKey theirIdentityKey = message.getIdentityKey();

            if (!identityKeyStore.isTrustedIdentity(remoteAddress, theirIdentityKey, IdentityKeyStore.Direction.RECEIVING))
            {
                throw new UntrustedIdentityException(remoteAddress.getName(), theirIdentityKey);
            }

            Optional<int> unsignedPreKeyId = processV3(sessionRecord, message);

            identityKeyStore.saveIdentity(remoteAddress, theirIdentityKey);

            return unsignedPreKeyId;
        }

        // throws UntrustedIdentityException, InvalidKeyIdException, InvalidKeyException
        private Optional<int> processV3(SessionRecord sessionRecord, PreKeySignalMessage message)

        

        {

            if (sessionRecord.hasSessionState(message.getMessageVersion(), message.getBaseKey().serialize()))
            {
                Log.w(TAG, "We've already setup a session for this V3 message, letting bundled message fall through...");
                return Optional.absent();
            }

            ECKeyPair ourSignedPreKey = signedPreKeyStore.loadSignedPreKey(message.getSignedPreKeyId()).getKeyPair();

            BobSignalProtocolParameters.Builder parameters = BobSignalProtocolParameters.newBuilder();

            parameters.setTheirBaseKey(message.getBaseKey()).setTheirIdentityKey(message.getIdentityKey()).setOurIdentityKey(identityKeyStore.getIdentityKeyPair()).setOurSignedPreKey(ourSignedPreKey).setOurRatchetKey(ourSignedPreKey);

            if (message.getPreKeyId().isPresent())
            {
                parameters.setOurOneTimePreKey(Optional.of(preKeyStore.loadPreKey(message.getPreKeyId().get()).getKeyPair()));
            }
            else
            {
                parameters.setOurOneTimePreKey(Optional. < ECKeyPair > absent());
            }

            if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

            sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.getLocalRegistrationId());
            sessionRecord.getSessionState().setRemoteRegistrationId(message.getRegistrationId());
            sessionRecord.getSessionState().setAliceBaseKey(message.getBaseKey().serialize());

            if (message.getPreKeyId().isPresent())
            {
                return message.getPreKeyId();
            }
            else
            {
                return Optional.absent();
            }
        }

        // throws InvalidKeyException, UntrustedIdentityException
        public void process(PreKeyBundle preKey)  {
            synchronized(SessionCipher.SESSION_LOCK) {
                if (!identityKeyStore.isTrustedIdentity(remoteAddress, preKey.getIdentityKey(), IdentityKeyStore.Direction.SENDING))
                {
                    throw new UntrustedIdentityException(remoteAddress.getName(), preKey.getIdentityKey());
                }

                if (preKey.getSignedPreKey() != null && !Curve.verifySignature(preKey.getIdentityKey().getPublicKey(), preKey.getSignedPreKey().serialize(), preKey.getSignedPreKeySignature()))
                {
                    throw new InvalidKeyException("Invalid signature on device key!");
                }

                if (preKey.getSignedPreKey() == null)
                {
                    throw new InvalidKeyException("No signed prekey!");
                }

                SessionRecord sessionRecord = sessionStore.loadSession(remoteAddress);
                ECKeyPair ourBaseKey = Curve.generateKeyPair();
                ECPublicKey theirSignedPreKey = preKey.getSignedPreKey();
                Optional<ECPublicKey> theirOneTimePreKey = Optional.fromNullable(preKey.getPreKey());
                Optional<int> theirOneTimePreKeyId = theirOneTimePreKey.isPresent() ? Optional.of(preKey.getPreKeyId()) : Optional.< Integer > absent();

                AliceSignalProtocolParameters.Builder parameters = AliceSignalProtocolParameters.newBuilder();

                parameters.setOurBaseKey(ourBaseKey).setOurIdentityKey(identityKeyStore.getIdentityKeyPair()).setTheirIdentityKey(preKey.getIdentityKey()).setTheirSignedPreKey(theirSignedPreKey).setTheirRatchetKey(theirSignedPreKey)
                    .setTheirOneTimePreKey(theirOneTimePreKey);

                if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

                RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

                sessionRecord.getSessionState().setUnacknowledgedPreKeyMessage(theirOneTimePreKeyId, preKey.getSignedPreKeyId(), ourBaseKey.getPublicKey());
                sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.getLocalRegistrationId());
                sessionRecord.getSessionState().setRemoteRegistrationId(preKey.getRegistrationId());
                sessionRecord.getSessionState().setAliceBaseKey(ourBaseKey.getPublicKey().serialize());

                identityKeyStore.saveIdentity(remoteAddress, preKey.getIdentityKey());
                sessionStore.storeSession(remoteAddress, sessionRecord);
            }
        }

    }
}


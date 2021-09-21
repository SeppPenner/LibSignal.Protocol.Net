namespace LibSignal.Protocol.Net
{
    using System;
    using System.Collections.Generic;

    using LibSignal.Protocol.Net.Ecc;
    using LibSignal.Protocol.Net.Protocol;
    using LibSignal.Protocol.Net.Ratchet;
    using LibSignal.Protocol.Net.State;
    using LibSignal.Protocol.Net.Util;
    using LibSignal.Protocol.Net.Util.Guava;

    public class SessionCipher
    {

        public static readonly object SESSION_LOCK = new object();

        private readonly SessionStore sessionStore;
        private readonly IdentityKeyStore identityKeyStore;
        private readonly SessionBuilder sessionBuilder;
        private readonly PreKeyStore preKeyStore;
        private readonly SignalProtocolAddress remoteAddress;


        public SessionCipher(SessionStore sessionStore, PreKeyStore preKeyStore,
                             SignedPreKeyStore signedPreKeyStore, IdentityKeyStore identityKeyStore,
                             SignalProtocolAddress remoteAddress)
        {
            this.sessionStore = sessionStore;
            this.preKeyStore = preKeyStore;
            this.identityKeyStore = identityKeyStore;
            this.remoteAddress = remoteAddress;
            this.sessionBuilder = new SessionBuilder(sessionStore, preKeyStore, signedPreKeyStore,
                                                       identityKeyStore, remoteAddress);
        }

        public SessionCipher(SignalProtocolStore store, SignalProtocolAddress remoteAddress)
        {
            this(store, store, store, store, remoteAddress);
        }

        // throws UntrustedIdentityException
        public CiphertextMessage encrypt(byte[] paddedMessage)
        {
            synchronized(SESSION_LOCK) {
                var sessionRecord = sessionStore.loadSession(remoteAddress);
                var sessionState = sessionRecord.getSessionState();
                var chainKey = sessionState.getSenderChainKey();
                var messageKeys = chainKey.getMessageKeys();
                var senderEphemeral = sessionState.getSenderRatchetKey();
                var previousCounter = sessionState.getPreviousCounter();
                var sessionVersion = sessionState.getSessionVersion();

                var ciphertextBody = getCiphertext(messageKeys, paddedMessage);
                CiphertextMessage ciphertextMessage = new SignalMessage(sessionVersion, messageKeys.getMacKey(),
                                                                        senderEphemeral, chainKey.getIndex(),
                                                                        previousCounter, ciphertextBody,
                                                                        sessionState.getLocalIdentityKey(),
                                                                        sessionState.getRemoteIdentityKey());

                if (sessionState.hasUnacknowledgedPreKeyMessage())
                {
                    var items = sessionState.getUnacknowledgedPreKeyMessageItems();
                    var localRegistrationId = sessionState.getLocalRegistrationId();

                    ciphertextMessage = new PreKeySignalMessage(sessionVersion, localRegistrationId, items.getPreKeyId(),
                                                                items.getSignedPreKeyId(), items.getBaseKey(),
                                                                sessionState.getLocalIdentityKey(),
                                                                (SignalMessage)ciphertextMessage);
                }

                sessionState.setSenderChainKey(chainKey.getNextChainKey());

                if (!identityKeyStore.isTrustedIdentity(remoteAddress, sessionState.getRemoteIdentityKey(), IdentityKeyStore.Direction.SENDING))
                {
                    throw new UntrustedIdentityException(remoteAddress.getName(), sessionState.getRemoteIdentityKey());
                }

                identityKeyStore.saveIdentity(remoteAddress, sessionState.getRemoteIdentityKey());
                sessionStore.storeSession(remoteAddress, sessionRecord);
                return ciphertextMessage;
            }
        }

        // throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, InvalidKeyIdException, InvalidKeyException, UntrustedIdentityException
        public byte[] decrypt(PreKeySignalMessage ciphertext)

        {
            return decrypt(ciphertext, new NullDecryptionCallback());
        }

        // throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, InvalidKeyIdException, InvalidKeyException, UntrustedIdentityException
        public byte[] decrypt(PreKeySignalMessage ciphertext, DecryptionCallback callback)

        {
            synchronized(SESSION_LOCK) {
                var sessionRecord = sessionStore.loadSession(remoteAddress);
                Optional<int> unsignedPreKeyId = sessionBuilder.process(sessionRecord, ciphertext);
                var plaintext = decrypt(sessionRecord, ciphertext.getWhisperMessage());

                callback.handlePlaintext(plaintext);

                sessionStore.storeSession(remoteAddress, sessionRecord);

                if (unsignedPreKeyId.isPresent())
                {
                    preKeyStore.removePreKey(unsignedPreKeyId.get());
                }

                return plaintext;
            }
        }

        // throws InvalidMessageException, DuplicateMessageException, LegacyMessageException, NoSessionException, UntrustedIdentityException
        public byte[] decrypt(SignalMessage ciphertext)

        {
            return decrypt(ciphertext, new NullDecryptionCallback());
        }

        // throws InvalidMessageException, DuplicateMessageException, LegacyMessageException, NoSessionException, UntrustedIdentityException
        public byte[] decrypt(SignalMessage ciphertext, DecryptionCallback callback)

        {
            synchronized(SESSION_LOCK) {

                if (!sessionStore.containsSession(remoteAddress))
                {
                    throw new NoSessionException("No session for: " + remoteAddress);
                }

                var sessionRecord = sessionStore.loadSession(remoteAddress);
                var plaintext = decrypt(sessionRecord, ciphertext);

                if (!identityKeyStore.isTrustedIdentity(remoteAddress, sessionRecord.getSessionState().getRemoteIdentityKey(), IdentityKeyStore.Direction.RECEIVING))
                {
                    throw new UntrustedIdentityException(remoteAddress.getName(), sessionRecord.getSessionState().getRemoteIdentityKey());
                }

                identityKeyStore.saveIdentity(remoteAddress, sessionRecord.getSessionState().getRemoteIdentityKey());

                callback.handlePlaintext(plaintext);

                sessionStore.storeSession(remoteAddress, sessionRecord);

                return plaintext;
            }
        }

        // throws DuplicateMessageException, LegacyMessageException, InvalidMessageException
        private byte[] decrypt(SessionRecord sessionRecord, SignalMessage ciphertext)

        {
            synchronized(SESSION_LOCK) {
                Iterator<SessionState> previousStates = sessionRecord.getPreviousSessionStates().iterator();
                List<Exception> exceptions = new LinkedList<>();

                try
                {
                    var sessionState = new SessionState(sessionRecord.getSessionState());
                    var plaintext = decrypt(sessionState, ciphertext);

                    sessionRecord.setState(sessionState);
                    return plaintext;
                }
                catch (InvalidMessageException e)
                {
                    exceptions.Add(e);
                }

                while (previousStates.hasNext())
                {
                    try
                    {
                        var promotedState = new SessionState(previousStates.next());
                        var plaintext = decrypt(promotedState, ciphertext);

                        previousStates.remove();
                        sessionRecord.promoteState(promotedState);

                        return plaintext;
                    }
                    catch (InvalidMessageException e)
                    {
                        exceptions.Add(e);
                    }
                }

                throw new InvalidMessageException("No valid sessions.", exceptions);
            }
        }

        //  throws InvalidMessageException, DuplicateMessageException, LegacyMessageException
        private byte[] decrypt(SessionState sessionState, SignalMessage ciphertextMessage)

        {
            if (!sessionState.hasSenderChain())
            {
                throw new InvalidMessageException("Uninitialized session!");
            }

            if (ciphertextMessage.getMessageVersion() != sessionState.getSessionVersion())
            {
                throw new InvalidMessageException(String.Format("Message version %d, but session version %d",
                                                                ciphertextMessage.getMessageVersion(),
                                                                sessionState.getSessionVersion()));
            }

            var theirEphemeral = ciphertextMessage.getSenderRatchetKey();
            var counter = ciphertextMessage.getCounter();
            var chainKey = getOrCreateChainKey(sessionState, theirEphemeral);
            var messageKeys = getOrCreateMessageKeys(sessionState, theirEphemeral,
                                                                      chainKey, counter);

            ciphertextMessage.verifyMac(sessionState.getRemoteIdentityKey(),
                                        sessionState.getLocalIdentityKey(),
                                        messageKeys.getMacKey());

            var plaintext = getPlaintext(messageKeys, ciphertextMessage.getBody());

            sessionState.clearUnacknowledgedPreKeyMessage();

            return plaintext;
        }

        public int getRemoteRegistrationId()
        {
            synchronized(SESSION_LOCK) {
                var record = sessionStore.loadSession(remoteAddress);
                return record.getSessionState().getRemoteRegistrationId();
            }
        }

        public int getSessionVersion()
        {
            synchronized(SESSION_LOCK) {
                if (!sessionStore.containsSession(remoteAddress))
                {
                    throw new IllegalStateException(string.Format("No session for (%s)!", remoteAddress));
                }

                var record = sessionStore.loadSession(remoteAddress);
                return record.getSessionState().getSessionVersion();
            }
        }

        // throws InvalidMessageException
        private ChainKey getOrCreateChainKey(SessionState sessionState, ECPublicKey theirEphemeral)

        {
            try
            {
                if (sessionState.hasReceiverChain(theirEphemeral))
                {
                    return sessionState.getReceiverChainKey(theirEphemeral);
                }
                else
                {
                    var rootKey = sessionState.getRootKey();
                    var ourEphemeral = sessionState.getSenderRatchetKeyPair();
                    var receiverChain = rootKey.createChain(theirEphemeral, ourEphemeral);
                    var ourNewEphemeral = Curve.generateKeyPair();
                    var senderChain = receiverChain.first().createChain(theirEphemeral, ourNewEphemeral);

                    sessionState.setRootKey(senderChain.first());
                    sessionState.addReceiverChain(theirEphemeral, receiverChain.second());
                    sessionState.setPreviousCounter(Math.Max(sessionState.getSenderChainKey().getIndex() - 1, 0));
                    sessionState.setSenderChain(ourNewEphemeral, senderChain.second());

                    return receiverChain.second();
                }
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        // throws InvalidMessageException, DuplicateMessageException
        private MessageKeys getOrCreateMessageKeys(SessionState sessionState,
                                                     ECPublicKey theirEphemeral,
                                                     ChainKey chainKey, int counter)

        {
            if (chainKey.getIndex() > counter)
            {
                if (sessionState.hasMessageKeys(theirEphemeral, counter))
                {
                    return sessionState.removeMessageKeys(theirEphemeral, counter);
                }
                else
                {
                    throw new DuplicateMessageException("Received message with old counter: " +
                                                            chainKey.getIndex() + " , " + counter);
                }
            }

            if (counter - chainKey.getIndex() > 2000)
            {
                throw new InvalidMessageException("Over 2000 messages into the future!");
            }

            while (chainKey.getIndex() < counter)
            {
                var messageKeys = chainKey.getMessageKeys();
                sessionState.setMessageKeys(theirEphemeral, messageKeys);
                chainKey = chainKey.getNextChainKey();
            }

            sessionState.setReceiverChainKey(theirEphemeral, chainKey.getNextChainKey());
            return chainKey.getMessageKeys();
        }

        private byte[] getCiphertext(MessageKeys messageKeys, byte[] plaintext)
        {
            try
            {
                Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
                return cipher.doFinal(plaintext);
            }
            catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new AssertionError(e);
            }
            }

            // throws InvalidMessageException
            private byte[] getPlaintext(MessageKeys messageKeys, byte[] cipherText)

            {
                try
                {
                    Cipher cipher = getCipher(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
                    return cipher.doFinal(cipherText);
                }
                catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new InvalidMessageException(e);
            }
        }

        private Cipher getCipher(int mode, SecretKeySpec key, IvParameterSpec iv)
        {
            try
            {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(mode, key, iv);
                return cipher;
            }
            catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException |
                   InvalidAlgorithmParameterException e)
    {
                throw new AssertionError(e);
            }
            }

  private static class NullDecryptionCallback : DecryptionCallback
        {
            public override void handlePlaintext(byte[] plaintext) { }
        }
    }
}
namespace LibSignal.Protocol.Net.Protocol
{
    using LibSignal.Protocol.Net.Ecc;
    using LibSignal.Protocol.Net.Util;
    using LibSignal.Protocol.Net.Util.Guava;


    public class PreKeySignalMessage : CiphertextMessage
    {

        private readonly int version;

        private readonly int registrationId;

        private readonly Optional<int> preKeyId;

        private readonly int signedPreKeyId;

        private readonly ECPublicKey baseKey;

        private readonly IdentityKey identityKey;

        private readonly SignalMessage message;

        private readonly byte[] serialized;

        // throws InvalidMessageException, InvalidVersionException
        public PreKeySignalMessage(byte[] serialized)

        {
            try
            {
                this.version = ByteUtil.highBitsToInt(serialized[0]);

                if (this.version > CiphertextMessage.CURRENT_VERSION)
                {
                    throw new InvalidVersionException("Unknown version: " + this.version);
                }

                if (this.version < CiphertextMessage.CURRENT_VERSION)
                {
                    throw new LegacyMessageException("Legacy version: " + this.version);
                }

                SignalProtos.PreKeySignalMessage preKeyWhisperMessage = SignalProtos.PreKeySignalMessage.parseFrom(ByteString.copyFrom(serialized, 1, serialized.Length - 1));

                if (!preKeyWhisperMessage.hasSignedPreKeyId() || !preKeyWhisperMessage.hasBaseKey() || !preKeyWhisperMessage.hasIdentityKey() || !preKeyWhisperMessage.hasMessage())
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this.serialized = serialized;
                this.registrationId = preKeyWhisperMessage.getRegistrationId();
                this.preKeyId = preKeyWhisperMessage.hasPreKeyId() ? Optional.of(preKeyWhisperMessage.getPreKeyId()) : Optional.< Integer > absent();
                this.signedPreKeyId = preKeyWhisperMessage.hasSignedPreKeyId() ? preKeyWhisperMessage.getSignedPreKeyId() : -1;
                this.baseKey = Curve.decodePoint(preKeyWhisperMessage.getBaseKey().toByteArray(), 0);
                this.identityKey = new IdentityKey(Curve.decodePoint(preKeyWhisperMessage.getIdentityKey().toByteArray(), 0));
                this.message = new SignalMessage(preKeyWhisperMessage.getMessage().toByteArray());
            }
            catch (InvalidProtocolBufferException |

            InvalidKeyException | LegacyMessageException e) {
                throw new InvalidMessageException(e);
            }
        }

        public PreKeySignalMessage(int messageVersion, int registrationId, Optional<int> preKeyId, int signedPreKeyId, ECPublicKey baseKey, IdentityKey identityKey, SignalMessage message)
        {
            this.version = messageVersion;
            this.registrationId = registrationId;
            this.preKeyId = preKeyId;
            this.signedPreKeyId = signedPreKeyId;
            this.baseKey = baseKey;
            this.identityKey = identityKey;
            this.message = message;

            SignalProtos.PreKeySignalMessage.Builder builder = SignalProtos.PreKeySignalMessage.newBuilder().setSignedPreKeyId(signedPreKeyId).setBaseKey(ByteString.copyFrom(baseKey.serialize()))
                .setIdentityKey(ByteString.copyFrom(identityKey.serialize())).setMessage(ByteString.copyFrom(message.serialize())).setRegistrationId(registrationId);

            if (preKeyId.isPresent())
            {
                builder.setPreKeyId(preKeyId.get());
            }

            byte[] versionBytes =
            {
                ByteUtil.intsToByteHighAndLow(this.version, CURRENT_VERSION)
            };
            byte[] messageBytes = builder.build().toByteArray();

            this.serialized = ByteUtil.combine(versionBytes, messageBytes);
        }

        public int getMessageVersion()
        {
            return version;
        }

        public IdentityKey getIdentityKey()
        {
            return identityKey;
        }

        public int getRegistrationId()
        {
            return registrationId;
        }

        public Optional<int> getPreKeyId()
        {
            return preKeyId;
        }

        public int getSignedPreKeyId()
        {
            return signedPreKeyId;
        }

        public ECPublicKey getBaseKey()
        {
            return baseKey;
        }

        public SignalMessage getWhisperMessage()
        {
            return message;
        }

        public override byte[] serialize()
        {
            return serialized;
        }

        public override int getType()
        {
            return CiphertextMessage.PREKEY_TYPE;
        }

    }

}



namespace LibSignal.Protocol.Net.Protocol
{
    using LibSignal.Protocol.Net.Ecc;
    using LibSignal.Protocol.Net.Util;


    public class SignalMessage : CiphertextMessage
    {

        private static readonly int MAC_LENGTH = 8;

        private readonly int messageVersion;

        private readonly ECPublicKey senderRatchetKey;

        private readonly int counter;

        private readonly int previousCounter;

        private readonly byte[] ciphertext;

        private readonly byte[] serialized;

        // throws InvalidMessageException, LegacyMessageException
        public SignalMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.split(serialized, 1, serialized.Length - 1 - MAC_LENGTH, MAC_LENGTH);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];
                byte[] mac = messageParts[2];

                if (ByteUtil.highBitsToInt(version) < CURRENT_VERSION)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
                }

                if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
                }

                SignalProtos.SignalMessage whisperMessage = SignalProtos.SignalMessage.parseFrom(message);

                if (!whisperMessage.hasCiphertext() || !whisperMessage.hasCounter() || !whisperMessage.hasRatchetKey())
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this.serialized = serialized;
                this.senderRatchetKey = Curve.decodePoint(whisperMessage.getRatchetKey().toByteArray(), 0);
                this.messageVersion = ByteUtil.highBitsToInt(version);
                this.counter = whisperMessage.getCounter();
                this.previousCounter = whisperMessage.getPreviousCounter();
                this.ciphertext = whisperMessage.getCiphertext().toByteArray();
            }
            catch (InvalidProtocolBufferException |

            InvalidKeyException | ParseException e) {
                throw new InvalidMessageException(e);
            }
        }

        public SignalMessage(int messageVersion, SecretKeySpec macKey, ECPublicKey senderRatchetKey, int counter, int previousCounter, byte[] ciphertext, IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey)
        {
            byte[] version =
            {
                ByteUtil.intsToByteHighAndLow(messageVersion, CURRENT_VERSION)
            };
            byte[] message = SignalProtos.SignalMessage.newBuilder().setRatchetKey(ByteString.copyFrom(senderRatchetKey.serialize())).setCounter(counter).setPreviousCounter(previousCounter).setCiphertext(ByteString.copyFrom(ciphertext)).build()
                .toByteArray();

            byte[] mac = getMac(senderIdentityKey, receiverIdentityKey, macKey, ByteUtil.combine(version, message));

            this.serialized = ByteUtil.combine(version, message, mac);
            this.senderRatchetKey = senderRatchetKey;
            this.counter = counter;
            this.previousCounter = previousCounter;
            this.ciphertext = ciphertext;
            this.messageVersion = messageVersion;
        }

        public ECPublicKey getSenderRatchetKey()
        {
            return senderRatchetKey;
        }

        public int getMessageVersion()
        {
            return messageVersion;
        }

        public int getCounter()
        {
            return counter;
        }

        public byte[] getBody()
        {
            return ciphertext;
        }

        // throws InvalidMessageException
        public void verifyMac(IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey, SecretKeySpec macKey)

        {
            byte[][] parts = ByteUtil.split(serialized, serialized.Length - MAC_LENGTH, MAC_LENGTH);
            byte[] ourMac = getMac(senderIdentityKey, receiverIdentityKey, macKey, parts[0]);
            byte[] theirMac = parts[1];

            if (!MessageDigest.isEqual(ourMac, theirMac))
            {
                throw new InvalidMessageException("Bad Mac!");
            }
        }

        private byte[] getMac(IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey, SecretKeySpec macKey, byte[] serialized)
        {
            try
            {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(macKey);

                mac.update(senderIdentityKey.getPublicKey().serialize());
                mac.update(receiverIdentityKey.getPublicKey().serialize());

                byte[] fullMac = mac.doFinal(serialized);
                return ByteUtil.trim(fullMac, MAC_LENGTH);
            }
            catch (NoSuchAlgorithmException |

            java.security.InvalidKeyException e) {
                throw new AssertionError(e);
            }
        }

        public override byte[] serialize()
        {
            return serialized;
        }

        public override int getType()
        {
            return CiphertextMessage.WHISPER_TYPE;
        }

        public static bool isLegacy(byte[] message)
        {
            return message != null && message.Length >= 1 && ByteUtil.highBitsToInt(message[0]) != CiphertextMessage.CURRENT_VERSION;
        }

    }

}
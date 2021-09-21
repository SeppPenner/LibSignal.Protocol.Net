namespace LibSignal.Protocol.Net.Protocol
{
    using LibSignal.Protocol.Net.Ecc;
    using LibSignal.Protocol.Net.Util;


    public class SenderKeyMessage : CiphertextMessage
    {

        private static readonly int SIGNATURE_LENGTH = 64;

        private readonly int messageVersion;

        private readonly int keyId;

        private readonly int iteration;

        private readonly byte[] ciphertext;

        private readonly byte[] serialized;

        // throws InvalidMessageException, LegacyMessageException
        public SenderKeyMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.split(serialized, 1, serialized.Length - 1 - SIGNATURE_LENGTH, SIGNATURE_LENGTH);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];
                byte[] signature = messageParts[2];

                if (ByteUtil.highBitsToInt(version) < 3)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
                }

                if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
                }

                SignalProtos.SenderKeyMessage senderKeyMessage = SignalProtos.SenderKeyMessage.parseFrom(message);

                if (!senderKeyMessage.hasId() || !senderKeyMessage.hasIteration() || !senderKeyMessage.hasCiphertext())
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this.serialized = serialized;
                this.messageVersion = ByteUtil.highBitsToInt(version);
                this.keyId = senderKeyMessage.getId();
                this.iteration = senderKeyMessage.getIteration();
                this.ciphertext = senderKeyMessage.getCiphertext().toByteArray();
            }
            catch (InvalidProtocolBufferException |

            ParseException e) {
                throw new InvalidMessageException(e);
            }
        }

        public SenderKeyMessage(int keyId, int iteration, byte[] ciphertext, ECPrivateKey signatureKey)
        {
            byte[] version =
            {
                ByteUtil.intsToByteHighAndLow(CURRENT_VERSION, CURRENT_VERSION)
            };
            byte[] message = SignalProtos.SenderKeyMessage.newBuilder().setId(keyId).setIteration(iteration).setCiphertext(ByteString.copyFrom(ciphertext)).build().toByteArray();

            byte[] signature = getSignature(signatureKey, ByteUtil.combine(version, message));

            this.serialized = ByteUtil.combine(version, message, signature);
            this.messageVersion = CURRENT_VERSION;
            this.keyId = keyId;
            this.iteration = iteration;
            this.ciphertext = ciphertext;
        }

        public int getKeyId()
        {
            return keyId;
        }

        public int getIteration()
        {
            return iteration;
        }

        public byte[] getCipherText()
        {
            return ciphertext;
        }

        // throws InvalidMessageException
        public void verifySignature(ECPublicKey signatureKey)

        {
            try
            {
                byte[][] parts = ByteUtil.split(serialized, serialized.Length - SIGNATURE_LENGTH, SIGNATURE_LENGTH);

                if (!Curve.verifySignature(signatureKey, parts[0], parts[1]))
                {
                    throw new InvalidMessageException("Invalid signature!");
                }

            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        private byte[] getSignature(ECPrivateKey signatureKey, byte[] serialized)
        {
            try
            {
                return Curve.calculateSignature(signatureKey, serialized);
            }
            catch (InvalidKeyException e)
            {
                throw new AssertionError(e);
            }
        }

        public override byte[] serialize()
        {
            return serialized;
        }

        public override int getType()
        {
            return CiphertextMessage.SENDERKEY_TYPE;
        }
    }

}


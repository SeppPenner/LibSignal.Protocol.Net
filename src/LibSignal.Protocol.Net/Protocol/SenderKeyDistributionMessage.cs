namespace LibSignal.Protocol.Net.Protocol
{
    using LibSignal.Protocol.Net.Ecc;
    using LibSignal.Protocol.Net.Util;


    public class SenderKeyDistributionMessage : CiphertextMessage
    {

        private readonly int id;

        private readonly int iteration;

        private readonly byte[] chainKey;

        private readonly ECPublicKey signatureKey;

        private readonly byte[] serialized;

        public SenderKeyDistributionMessage(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey)
        {
            byte[] version =
            {
                ByteUtil.intsToByteHighAndLow(CURRENT_VERSION, CURRENT_VERSION)
            };
            byte[] protobuf = SignalProtos.SenderKeyDistributionMessage.newBuilder().setId(id).setIteration(iteration).setChainKey(ByteString.copyFrom(chainKey)).setSigningKey(ByteString.copyFrom(signatureKey.serialize())).build().toByteArray();

            this.id = id;
            this.iteration = iteration;
            this.chainKey = chainKey;
            this.signatureKey = signatureKey;
            this.serialized = ByteUtil.combine(version, protobuf);
        }

        // throws LegacyMessageException, InvalidMessageException
        public SenderKeyDistributionMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.split(serialized, 1, serialized.Length - 1);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];

                if (ByteUtil.highBitsToInt(version) < CiphertextMessage.CURRENT_VERSION)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
                }

                if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
                }

                SignalProtos.SenderKeyDistributionMessage distributionMessage = SignalProtos.SenderKeyDistributionMessage.parseFrom(message);

                if (!distributionMessage.hasId() || !distributionMessage.hasIteration() || !distributionMessage.hasChainKey() || !distributionMessage.hasSigningKey())
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this.serialized = serialized;
                this.id = distributionMessage.getId();
                this.iteration = distributionMessage.getIteration();
                this.chainKey = distributionMessage.getChainKey().toByteArray();
                this.signatureKey = Curve.decodePoint(distributionMessage.getSigningKey().toByteArray(), 0);
            }
            catch (InvalidProtocolBufferException |

            InvalidKeyException e) {
                throw new InvalidMessageException(e);
            }
        }

        public override byte[] serialize()
        {
            return serialized;
        }

        public override int getType()
        {
            return SENDERKEY_DISTRIBUTION_TYPE;
        }

        public int getIteration()
        {
            return iteration;
        }

        public byte[] getChainKey()
        {
            return chainKey;
        }

        public ECPublicKey getSignatureKey()
        {
            return signatureKey;
        }

        public int getId()
        {
            return id;
        }
    }
}
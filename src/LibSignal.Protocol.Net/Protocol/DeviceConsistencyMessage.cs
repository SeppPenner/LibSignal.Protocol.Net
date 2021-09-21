namespace LibSignal.Protocol.Net.Protocol
{
    using LibSignal.Protocol.Net.Devices;
    using LibSignal.Protocol.Net.Ecc;


    public class DeviceConsistencyMessage
    {

        private readonly DeviceConsistencySignature  signature;
  private readonly int generation;
        private readonly byte[] serialized;

        public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, IdentityKeyPair identityKeyPair)
        {
            try
            {
                byte[] signatureBytes = Curve.calculateVrfSignature(identityKeyPair.getPrivateKey(), commitment.toByteArray());
                byte[] vrfOutputBytes = Curve.verifyVrfSignature(identityKeyPair.getPublicKey().getPublicKey(), commitment.toByteArray(), signatureBytes);

                this.generation = commitment.getGeneration();
                this.signature = new DeviceConsistencySignature(signatureBytes, vrfOutputBytes);
                this.serialized = SignalProtos.DeviceConsistencyCodeMessage.newBuilder()
                                                                            .setGeneration(commitment.getGeneration())
                                                                            .setSignature(ByteString.copyFrom(signature.getSignature()))
                                                                            .build()
                                                                            .toByteArray();
            }
            catch (InvalidKeyException | VrfSignatureVerificationFailedException e) {
                throw new AssertionError(e);
            }
            }

            // throws InvalidMessageException
            public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, byte[] serialized, IdentityKey identityKey)  {
                try
                {
                    SignalProtos.DeviceConsistencyCodeMessage message = SignalProtos.DeviceConsistencyCodeMessage.parseFrom(serialized);
                    byte[] vrfOutputBytes = Curve.verifyVrfSignature(identityKey.getPublicKey(), commitment.toByteArray(), message.getSignature().toByteArray());

                    this.generation = message.getGeneration();
                    this.signature = new DeviceConsistencySignature(message.getSignature().toByteArray(), vrfOutputBytes);
                    this.serialized = serialized;
                }
                catch (InvalidProtocolBufferException | InvalidKeyException | VrfSignatureVerificationFailedException e) {
                    throw new InvalidMessageException(e);
                }
                }

                public byte[] getSerialized()
                {
                    return serialized;
                }

                public DeviceConsistencySignature getSignature()
                {
                    return signature;
                }

                public int getGeneration()
                {
                    return generation;
                }
            }
        }

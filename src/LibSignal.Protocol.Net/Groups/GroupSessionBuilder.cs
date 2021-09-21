namespace LibSignal.Protocol.Net.Groups
{
    using LibSignal.Protocol.Net.Groups.State;
    using LibSignal.Protocol.Net.Protocol;
    using LibSignal.Protocol.Net.Util;


    public class GroupSessionBuilder
    {

        private readonly SenderKeyStore senderKeyStore;

  public GroupSessionBuilder(SenderKeyStore senderKeyStore)
        {
            this.senderKeyStore = senderKeyStore;
        }

        public void process(SenderKeyName senderKeyName, SenderKeyDistributionMessage senderKeyDistributionMessage)
        {
            synchronized(GroupCipher.LOCK) {
                SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);
                senderKeyRecord.addSenderKeyState(senderKeyDistributionMessage.getId(),
                                                  senderKeyDistributionMessage.getIteration(),
                                                  senderKeyDistributionMessage.getChainKey(),
                                                  senderKeyDistributionMessage.getSignatureKey());
                senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
            }
        }

        public SenderKeyDistributionMessage create(SenderKeyName senderKeyName)
        {
            synchronized(GroupCipher.LOCK) {
                try
                {
                    SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);

                    if (senderKeyRecord.isEmpty())
                    {
                        senderKeyRecord.setSenderKeyState(KeyHelper.generateSenderKeyId(),
                                                          0,
                                                          KeyHelper.generateSenderKey(),
                                                          KeyHelper.generateSenderSigningKey());
                        senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
                    }

                    SenderKeyState state = senderKeyRecord.getSenderKeyState();

                    return new SenderKeyDistributionMessage(state.getKeyId(),
                                                            state.getSenderChainKey().getIteration(),
                                                            state.getSenderChainKey().getSeed(),
                                                            state.getSigningKeyPublic());

                }
                catch (InvalidKeyIdException | InvalidKeyException e) {
                    throw new AssertionError(e);
                }
                }
            }
        }
    }


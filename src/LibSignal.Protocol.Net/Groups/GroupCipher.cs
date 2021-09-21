namespace LibSignal.Protocol.Net.Groups
{
    using LibSignal.Protocol.Net.Groups.Ratchet;
    using LibSignal.Protocol.Net.Groups.State;
    using LibSignal.Protocol.Net.Protocol;


    public class GroupCipher
    {

        static readonly object LOCK = new object();

        private readonly SenderKeyStore senderKeyStore;
  private readonly SenderKeyName senderKeyId;

  public GroupCipher(SenderKeyStore senderKeyStore, SenderKeyName senderKeyId)
        {
            this.senderKeyStore = senderKeyStore;
            this.senderKeyId = senderKeyId;
        }

        // throws NoSessionException
        public byte[] encrypt(byte[] paddedPlaintext) 
        {
            synchronized (LOCK) {
      try {
        SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyId);
        SenderKeyState senderKeyState = record.getSenderKeyState();
        SenderMessageKey senderKey = senderKeyState.getSenderChainKey().getSenderMessageKey();
        byte[] ciphertext = getCipherText(senderKey.getIv(), senderKey.getCipherKey(), paddedPlaintext);

        SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyState.getKeyId(),
                                                                 senderKey.getIteration(),
                                                                 ciphertext,
                                                                 senderKeyState.getSigningKeyPrivate());

        senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext());

        senderKeyStore.storeSenderKey(senderKeyId, record);

        return senderKeyMessage.serialize();
      } catch (InvalidKeyIdException e) {
        throw new NoSessionException(e);
}
    }
  }

        // throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
public byte[] decrypt(byte[] senderKeyMessageBytes)
      
  {
    return decrypt(senderKeyMessageBytes, new NullDecryptionCallback());
  }

//  throws LegacyMessageException, InvalidMessageException, DuplicateMessageException, NoSessionException
  public byte[] decrypt(byte[] senderKeyMessageBytes, DecryptionCallback callback)
     
  {
    synchronized (LOCK) {
    try
    {
        SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyId);

        if (record.isEmpty())
        {
            throw new NoSessionException("No sender key for: " + senderKeyId);
        }

        SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyMessageBytes);
        SenderKeyState senderKeyState = record.getSenderKeyState(senderKeyMessage.getKeyId());

        senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic());

        SenderMessageKey senderKey = getSenderKey(senderKeyState, senderKeyMessage.getIteration());

        byte[] plaintext = getPlainText(senderKey.getIv(), senderKey.getCipherKey(), senderKeyMessage.getCipherText());

        callback.handlePlaintext(plaintext);

        senderKeyStore.storeSenderKey(senderKeyId, record);

        return plaintext;
    }
    catch (org.whispersystems.libsignal.InvalidKeyException | InvalidKeyIdException e) {
        throw new InvalidMessageException(e);
    }
    }
}

  // throws DuplicateMessageException, InvalidMessageException
            private SenderMessageKey getSenderKey(SenderKeyState senderKeyState, int iteration)
      
  {
    SenderChainKey senderChainKey = senderKeyState.getSenderChainKey();

if (senderChainKey.getIteration() > iteration)
{
    if (senderKeyState.hasSenderMessageKey(iteration))
    {
        return senderKeyState.removeSenderMessageKey(iteration);
    }
    else
    {
        throw new DuplicateMessageException("Received message with old counter: " +
                                            senderChainKey.getIteration() + " , " + iteration);
    }
}

if (iteration - senderChainKey.getIteration() > 2000)
{
    throw new InvalidMessageException("Over 2000 messages into the future!");
}

while (senderChainKey.getIteration() < iteration)
{
    senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey());
    senderChainKey = senderChainKey.getNext();
}

senderKeyState.setSenderChainKey(senderChainKey.getNext());
return senderChainKey.getSenderMessageKey();
  }

            // throws InvalidMessageException
private byte[] getPlainText(byte[] iv, byte[] key, byte[] ciphertext)
      
{
    try {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);

        return cipher.doFinal(ciphertext);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException |
             InvalidAlgorithmParameterException e)
    {
        throw new AssertionError(e);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
        throw new InvalidMessageException(e);
    }
}

private byte[] getCipherText(byte[] iv, byte[] key, byte[] plaintext)
{
    try
    {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);

        return cipher.doFinal(plaintext);
    }
    catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
           IllegalBlockSizeException | BadPaddingException | java.security.InvalidKeyException e)
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


namespace LibSignal.Protocol.Net
{
    public interface DecryptionCallback
    {
        public void handlePlaintext(byte[] plaintext);
    }
}

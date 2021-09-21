namespace LibSignal.Protocol.Net.Ecc
{
    public interface ECPrivateKey
    {
        public byte[] serialize();
        public int getType();
    }

}
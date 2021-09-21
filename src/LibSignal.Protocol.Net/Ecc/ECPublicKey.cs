namespace LibSignal.Protocol.Net.Ecc
{
    using System;

    public interface ECPublicKey : IComparable<ECPublicKey>
    {
        public static readonly int KEY_SIZE = 33;

        public byte[] serialize();

        public int getType();
    }
}

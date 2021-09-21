namespace LibSignal.Protocol.Net
{
    using System;


    public class UntrustedIdentityException : Exception
    {

        private readonly string name;

        private readonly IdentityKey key;

        public UntrustedIdentityException(string name, IdentityKey key)
        {
            this.name = name;
            this.key = key;
        }

        public IdentityKey getUntrustedIdentity()
        {
            return key;
        }

        public string getName()
        {
            return name;
        }
    }
}

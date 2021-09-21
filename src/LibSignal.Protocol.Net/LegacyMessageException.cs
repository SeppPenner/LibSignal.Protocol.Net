namespace LibSignal.Protocol.Net
{
    using System;


    public class LegacyMessageException : Exception
    {
        public LegacyMessageException(string s) : base(s) {}
    }
}

namespace LibSignal.Protocol.Net
{
    using System;

    public class NoSessionException : Exception
    {
        public NoSessionException(string s) : base(s) {}

        public NoSessionException(Exception nested) : base(nested.Message, nested) {}
    }

}
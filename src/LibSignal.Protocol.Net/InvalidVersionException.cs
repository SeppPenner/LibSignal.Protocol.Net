namespace LibSignal.Protocol.Net
{
    using System;


    public class InvalidVersionException : Exception
    {
        public InvalidVersionException(string detailMessage) : base(detailMessage) {}
    }

}

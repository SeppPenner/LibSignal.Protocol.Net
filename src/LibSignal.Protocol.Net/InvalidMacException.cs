namespace LibSignal.Protocol.Net
{
    using System;


    public class InvalidMacException : Exception
    {

        public InvalidMacException(string detailMessage) : base(detailMessage)
        {
        }

        public InvalidMacException(Throwable throwable) : base(throwable)
        {
        }
    }
}

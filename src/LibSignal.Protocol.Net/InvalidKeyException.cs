namespace LibSignal.Protocol.Net
{
    using System;


    public class InvalidKeyException : Exception
    {

        public InvalidKeyException() { }

        public InvalidKeyException(string detailMessage) : base(detailMessage)
        {
        }

        public InvalidKeyException(Throwable throwable) : base (throwable)
        {
        }

        public InvalidKeyException(string detailMessage, Throwable throwable) : base(detailMessage, throwable)
        {
        }
    }

}


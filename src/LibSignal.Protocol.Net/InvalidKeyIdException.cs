namespace LibSignal.Protocol.Net
{
    using System;


    public class InvalidKeyIdException : Exception
    {
        public InvalidKeyIdException(string detailMessage) : base(detailMessage) {}

        public InvalidKeyIdException(Throwable throwable) : base(throwable) {}
    }

}


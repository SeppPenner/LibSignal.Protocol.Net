namespace LibSignal.Protocol.Net
{
    using System;
    using System.Collections.Generic;


    public class InvalidMessageException : Exception
    {

        public InvalidMessageException() {}

        public InvalidMessageException(string detailMessage)
            : base(detailMessage) {}

        public InvalidMessageException(Throwable throwable)
            : base(throwable) {}

        public InvalidMessageException(string detailMessage, Throwable throwable)
            : base(detailMessage, throwable) {}

        public InvalidMessageException(String detailMessage, List<Exception> exceptions)
            : base(detailMessage, exceptions.get(0)) {}
    }

}


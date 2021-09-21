namespace LibSignal.Protocol.Net
{
    using System;


    public class DuplicateMessageException : Exception
    {
        public DuplicateMessageException(string s) : base(s) {}
    }
}

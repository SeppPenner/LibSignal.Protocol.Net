namespace LibSignal.Protocol.Net.Fingerprint
{
    using System;

    public class FingerprintParsingException : Exception
    {

        public FingerprintParsingException(Exception nested) : base(nested.Message, nested) {}

    }
}
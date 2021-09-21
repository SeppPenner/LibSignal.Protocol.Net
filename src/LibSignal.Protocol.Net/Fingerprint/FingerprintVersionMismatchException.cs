namespace LibSignal.Protocol.Net.Fingerprint
{
    using System;

    public class FingerprintVersionMismatchException : Exception
    {

        private readonly int theirVersion;
        private readonly int ourVersion;

        public FingerprintVersionMismatchException(int theirVersion, int ourVersion)
        {
            this.theirVersion = theirVersion;
            this.ourVersion = ourVersion;
        }

        public int getTheirVersion()
        {
            return theirVersion;
        }

        public int getOurVersion()
        {
            return ourVersion;
        }
    }
}

namespace LibSignal.Protocol.Net.Fingerprint
{
    using System;

    public class FingerprintIdentifierMismatchException : Exception
    {

        private readonly string localIdentifier;
        private readonly string remoteIdentifier;
        private readonly string scannedLocalIdentifier;
        private readonly string scannedRemoteIdentifier;

        public FingerprintIdentifierMismatchException(string localIdentifier, string remoteIdentifier,
                                                      string scannedLocalIdentifier, string scannedRemoteIdentifier)
        {
            this.localIdentifier = localIdentifier;
            this.remoteIdentifier = remoteIdentifier;
            this.scannedLocalIdentifier = scannedLocalIdentifier;
            this.scannedRemoteIdentifier = scannedRemoteIdentifier;
        }

        public string getScannedRemoteIdentifier()
        {
            return scannedRemoteIdentifier;
        }

        public string getScannedLocalIdentifier()
        {
            return scannedLocalIdentifier;
        }

        public string getRemoteIdentifier()
        {
            return remoteIdentifier;
        }

        public string getLocalIdentifier()
        {
            return localIdentifier;
        }
    }
}

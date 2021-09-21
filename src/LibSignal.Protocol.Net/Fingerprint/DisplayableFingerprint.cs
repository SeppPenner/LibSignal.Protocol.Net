namespace LibSignal.Protocol.Net.Fingerprint
{
    using System;

    using LibSignal.Protocol.Net.Util;


    public class DisplayableFingerprint
    {

        private readonly string localFingerprintNumbers;
        private readonly string remoteFingerprintNumbers;

        DisplayableFingerprint(byte[] localFingerprint, byte[] remoteFingerprint)
        {
            this.localFingerprintNumbers = getDisplayStringFor(localFingerprint);
            this.remoteFingerprintNumbers = getDisplayStringFor(remoteFingerprint);
        }

        public String getDisplayText()
        {
            if (localFingerprintNumbers.CompareTo(remoteFingerprintNumbers) <= 0)
            {
                return localFingerprintNumbers + remoteFingerprintNumbers;
            }
            else
            {
                return remoteFingerprintNumbers + localFingerprintNumbers;
            }
        }

        private String getDisplayStringFor(byte[] fingerprint)
        {
            return getEncodedChunk(fingerprint, 0) +
                   getEncodedChunk(fingerprint, 5) +
                   getEncodedChunk(fingerprint, 10) +
                   getEncodedChunk(fingerprint, 15) +
                   getEncodedChunk(fingerprint, 20) +
                   getEncodedChunk(fingerprint, 25);
        }

        private String getEncodedChunk(byte[] hash, int offset)
        {
            long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
            return string.Format("%05d", chunk);
        }
    }
}


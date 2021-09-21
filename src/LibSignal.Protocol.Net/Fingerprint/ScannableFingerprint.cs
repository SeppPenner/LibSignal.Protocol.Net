namespace LibSignal.Protocol.Net.Fingerprint
{
    using LibSignal.Protocol.Net.Util;


    public class ScannableFingerprint
    {

        private readonly int version;

        private readonly CombinedFingerprints fingerprints;

        ScannableFingerprint(int version, byte[] localFingerprintData, byte[] remoteFingerprintData)
        {
            LogicalFingerprint localFingerprint = LogicalFingerprint.newBuilder().setContent(ByteString.copyFrom(ByteUtil.trim(localFingerprintData, 32))).build();

            LogicalFingerprint remoteFingerprint = LogicalFingerprint.newBuilder().setContent(ByteString.copyFrom(ByteUtil.trim(remoteFingerprintData, 32))).build();

            this.version = version;
            this.fingerprints = CombinedFingerprints.newBuilder().setVersion(version).setLocalFingerprint(localFingerprint).setRemoteFingerprint(remoteFingerprint).build();
        }

        public byte[] getSerialized()
        {
            return fingerprints.toByteArray();
        }

        // throws FingerprintVersionMismatchException,FingerprintParsingException
        public bool compareTo(byte[] scannedFingerprintData)

        {
            try
            {
                CombinedFingerprints scanned = CombinedFingerprints.parseFrom(scannedFingerprintData);

                if (!scanned.hasRemoteFingerprint() || !scanned.hasLocalFingerprint() || !scanned.hasVersion() || scanned.getVersion() != version)
                {
                    throw new FingerprintVersionMismatchException(scanned.getVersion(), version);
                }

                return MessageDigest.isEqual(fingerprints.getLocalFingerprint().getContent().toByteArray(), scanned.getRemoteFingerprint().getContent().toByteArray()) && MessageDigest.isEqual(
                           fingerprints.getRemoteFingerprint().getContent().toByteArray(),
                           scanned.getLocalFingerprint().getContent().toByteArray());
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new FingerprintParsingException(e);
            }
        }
    }
}

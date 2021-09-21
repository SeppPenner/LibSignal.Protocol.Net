namespace LibSignal.Protocol.Net.Devices
{
    using System.Collections.Generic;

    using LibSignal.Protocol.Net.Util;


    public class DeviceConsistencyCodeGenerator
    {

        private static readonly int CODE_VERSION = 0;

        public static string generateFor(DeviceConsistencyCommitment commitment, List<DeviceConsistencySignature> signatures)
        {
            try
            {
                var sortedSignatures = new List<DeviceConsistencySignature>(signatures);
                Collections.sort(sortedSignatures, new SignatureComparator());

                MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
                messageDigest.update(ByteUtil.shortToByteArray(CODE_VERSION));
                messageDigest.update(commitment.toByteArray());

                for (DeviceConsistencySignature signature :
                sortedSignatures)
                {
                    messageDigest.update(signature.getVrfOutput());
                }

                byte[] hash = messageDigest.digest();

                string digits = getEncodedChunk(hash, 0) + getEncodedChunk(hash, 5);
                return digits.substring(0, 6);

            }
            catch (NoSuchAlgorithmException e)
            {
                throw new AssertionError(e);
            }
        }

        private static string getEncodedChunk(byte[] hash, int offset)
        {
            long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
            return string.format("%05d", chunk);
        }

        //Extends, implements
        private static class SignatureComparator : ByteArrayComparator, Comparator<DeviceConsistencySignature>

        {
        public override int compare(DeviceConsistencySignature first, DeviceConsistencySignature second)
        {
            return compare(first.getVrfOutput(), second.getVrfOutput());
        }
    }
}
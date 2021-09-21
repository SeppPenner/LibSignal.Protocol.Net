namespace LibSignal.Protocol.Net.Devices
{
    using System.Collections.Generic;

    using LibSignal.Protocol.Net.Util;


    public class DeviceConsistencyCommitment
    {

        private static readonly string VERSION = "DeviceConsistencyCommitment_V0";

        private readonly int generation;
        private readonly byte[] serialized;

        public DeviceConsistencyCommitment(int generation, List<IdentityKey> identityKeys)
        {
            try
            {
                List<IdentityKey> sortedIdentityKeys = new List<IdentityKey>(identityKeys);
                Collections.sort(sortedIdentityKeys, new IdentityKeyComparator());

                MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
                messageDigest.update(VERSION.getBytes());
                messageDigest.update(ByteUtil.intToByteArray(generation));

                foreach (IdentityKey commitment in sortedIdentityKeys)
                {
                    messageDigest.update(commitment.getPublicKey().serialize());
                }

                this.generation = generation;
                this.serialized = messageDigest.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new AssertionError(e);
            }
        }

        public byte[] toByteArray()
        {
            return serialized;
        }

        public int getGeneration()
        {
            return generation;
        }


    }
}



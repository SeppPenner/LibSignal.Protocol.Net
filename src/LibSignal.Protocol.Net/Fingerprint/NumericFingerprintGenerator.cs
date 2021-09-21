namespace LibSignal.Protocol.Net.Fingerprint
{
    using System.Collections.Generic;

    using LibSignal.Protocol.Net.Util;

    public class NumericFingerprintGenerator : FingerprintGenerator
    {

        private static readonly int FINGERPRINT_VERSION = 0;

        private readonly int iterations;


        public NumericFingerprintGenerator(int iterations)
        {
            this.iterations = iterations;
        }


        public override Fingerprint createFor(int version, byte[] localStableIdentifier, final IdentityKey localIdentityKey,

        byte[] remoteStableIdentifier, final IdentityKey remoteIdentityKey)
        {
            return createFor(
                version,
                localStableIdentifier,
                new LinkedList<IdentityKey>()
                {
                    {
                        add(localIdentityKey);
                    }
                },
                remoteStableIdentifier,
                new LinkedList<IdentityKey>()
                {
                    {
                        add(remoteIdentityKey);
                    }
                });
        }


        public override Fingerprint createFor(int version, byte[] localStableIdentifier, List<IdentityKey> localIdentityKeys, byte[] remoteStableIdentifier, List<IdentityKey> remoteIdentityKeys)
        {
            byte[] localFingerprint = getFingerprint(iterations, localStableIdentifier, localIdentityKeys);
            byte[] remoteFingerprint = getFingerprint(iterations, remoteStableIdentifier, remoteIdentityKeys);

            DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(localFingerprint, remoteFingerprint);

            ScannableFingerprint scannableFingerprint = new ScannableFingerprint(version, localFingerprint, remoteFingerprint);

            return new Fingerprint(displayableFingerprint, scannableFingerprint);
        }

        private byte[] getFingerprint(int iterations, byte[] stableIdentifier, List<IdentityKey> unsortedIdentityKeys)
        {
            try
            {
                MessageDigest digest = MessageDigest.getInstance("SHA-512");
                byte[] publicKey = getLogicalKeyBytes(unsortedIdentityKeys);
                byte[] hash = ByteUtil.combine(ByteUtil.shortToByteArray(FINGERPRINT_VERSION), publicKey, stableIdentifier);

                for (int i = 0; i < iterations; i++)
                {
                    digest.update(hash);
                    hash = digest.digest(publicKey);
                }

                return hash;
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new AssertionError(e);
            }
        }

        private byte[] getLogicalKeyBytes(List<IdentityKey> identityKeys)
        {
            ArrayList<IdentityKey> sortedIdentityKeys = new ArrayList<>(identityKeys);
            Collections.sort(sortedIdentityKeys, new IdentityKeyComparator());

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            for (IdentityKey identityKey :
            sortedIdentityKeys) {
                byte[] publicKeyBytes = identityKey.getPublicKey().serialize();
                baos.write(publicKeyBytes, 0, publicKeyBytes.length);
            }

            return baos.toByteArray();
        }


    }

}


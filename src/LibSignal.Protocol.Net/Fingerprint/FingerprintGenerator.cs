namespace LibSignal.Protocol.Net.Fingerprint
{
    using System.Collections.Generic;

    public interface FingerprintGenerator
    {
        public Fingerprint createFor(int version,
                                     byte[] localStableIdentifier,
                                     IdentityKey localIdentityKey,
                                     byte[] remoteStableIdentifier,
                                     IdentityKey remoteIdentityKey);

        public Fingerprint createFor(int version,
                                     byte[] localStableIdentifier,
                                     List<IdentityKey> localIdentityKey,
                                     byte[] remoteStableIdentifier,
                                     List<IdentityKey> remoteIdentityKey);
    }
}

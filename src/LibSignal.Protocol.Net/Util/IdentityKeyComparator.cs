namespace LibSignal.Protocol.Net.Util
{
    // Extends, implements
    public class IdentityKeyComparator : ByteArrayComparator, Comparator<IdentityKey>
    {

        public override int compare(IdentityKey first, IdentityKey second)
        {
            return compare(first.getPublicKey().serialize(), second.getPublicKey().serialize());
        }
    }
}


namespace LibSignal.Protocol.Net.Util
{
    public abstract class ByteArrayComparator
    {

        protected int compare(byte[] left, byte[] right)
        {
            for (int i = 0, j = 0; i < left.Length && j < right.Length; i++, j++)
            {
                var a = (left[i] & 0xff);
                var b = (right[j] & 0xff);

                if (a != b)
                {
                    return a - b;
                }
            }

            return left.Length - right.Length;
        }

    }
}

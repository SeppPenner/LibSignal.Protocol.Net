namespace LibSignal.Protocol.Net.Kdf
{
    public class HKDFv2 : HKDF
    {
        protected override int getIterationStartOffset()
        {
            return 0;
        }
    }
}

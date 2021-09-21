namespace LibSignal.Protocol.Net.Devices
{
    public class DeviceConsistencySignature
    {

        private readonly byte[] signature;
        private readonly byte[] vrfOutput;

        public DeviceConsistencySignature(byte[] signature, byte[] vrfOutput)
        {
            this.signature = signature;
            this.vrfOutput = vrfOutput;
        }

        public byte[] getVrfOutput()
        {
            return vrfOutput;
        }

        public byte[] getSignature()
        {
            return signature;
        }
    }
}
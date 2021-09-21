namespace LibSignal.Protocol.Net
{
    public class SignalProtocolAddress
    {

        private readonly string name;
        private readonly int deviceId;

        public SignalProtocolAddress(string name, int deviceId)
        {
            this.name = name;
            this.deviceId = deviceId;
        }

        public string getName()
        {
            return name;
        }

        public int getDeviceId()
        {
            return deviceId;
        }

        public override string toString()
        {
            return name + ":" + deviceId;
        }

        public override bool equals(object other)
        {
            if (other == null) return false;
            if (!(other instanceof SignalProtocolAddress)) return false;

            SignalProtocolAddress that = (SignalProtocolAddress)other;
            return this.name.equals(that.name) && this.deviceId == that.deviceId;
        }

        public override int hashCode()
        {
            return this.name.hashCode() ^ this.deviceId;
        }
    }
}

namespace LibSignal.Protocol.Net.Groups
{
    using System;

    public class SenderKeyName
    {

        private readonly string groupId;
        private readonly SignalProtocolAddress sender;

        public SenderKeyName(string groupId, SignalProtocolAddress sender)
        {
            this.groupId = groupId;
            this.sender = sender;
        }

        public string getGroupId()
        {
            return groupId;
        }

        public SignalProtocolAddress getSender()
        {
            return sender;
        }

        public string serialize()
        {
            return groupId + "::" + sender.getName() + "::" + string.valueOf(sender.getDeviceId());
        }

        public override bool equals(Object other)
        {
            if (other == null) return false;
            if (!(other instanceof SenderKeyName)) return false;

            SenderKeyName that = (SenderKeyName)other;

            return
                this.groupId.Equals(that.groupId) &&
                this.sender.equals(that.sender);
        }

        public override int hashCode()
        {
            return this.groupId.hashCode() ^ this.sender.hashCode();
        }

    }
}

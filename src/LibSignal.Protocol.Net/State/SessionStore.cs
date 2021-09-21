namespace LibSignal.Protocol.Net.State
{
    using System.Collections.Generic;

    public interface SessionStore
    {

        public SessionRecord loadSession(SignalProtocolAddress address);

        public List<int> getSubDeviceSessions(string name);


        public void storeSession(SignalProtocolAddress address, SessionRecord record);

        public bool containsSession(SignalProtocolAddress address);

        public void deleteSession(SignalProtocolAddress address);


        public void deleteAllSessions(string name);

    }
}
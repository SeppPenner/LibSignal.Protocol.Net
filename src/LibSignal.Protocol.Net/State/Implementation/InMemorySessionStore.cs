namespace LibSignal.Protocol.Net.State.Implementation
{
    using System;
    using System.Collections.Generic;
    using System.IO;


    public class InMemorySessionStore : SessionStore
    {

        private Map<SignalProtocolAddress, byte[]> sessions = new HashMap<>();

        public InMemorySessionStore() { }

        public override synchronized SessionRecord loadSession(SignalProtocolAddress remoteAddress)
        {
            try
            {
                if (containsSession(remoteAddress))
                {
                    return new SessionRecord(sessions.get(remoteAddress));
                }
                else
                {
                    return new SessionRecord();
                }
            }
            catch (IOException e)
            {
                throw new AssertionError(e);
            }
        }

        public override synchronized List<Integer> getSubDeviceSessions(string name)
        {
            var deviceIds = new LinkedList<int>();

            for (SignalProtocolAddress key : sessions.keySet())
            {
                if (key.getName().equals(name) &&
                    key.getDeviceId() != 1)
                {
                    deviceIds.Add(key.getDeviceId());
                }
            }

            return deviceIds;
        }

        public override synchronized void storeSession(SignalProtocolAddress address, SessionRecord record)
        {
            sessions.put(address, record.serialize());
        }

        public override synchronized boolean containsSession(SignalProtocolAddress address)
        {
            return sessions.containsKey(address);
        }

        public override synchronized void deleteSession(SignalProtocolAddress address)
        {
            sessions.remove(address);
        }

        public override synchronized void deleteAllSessions(string name)
        {
            for (SignalProtocolAddress key : sessions.keySet())
            {
                if (key.getName().equals(name))
                {
                    sessions.remove(key);
                }
            }
        }
    }

}



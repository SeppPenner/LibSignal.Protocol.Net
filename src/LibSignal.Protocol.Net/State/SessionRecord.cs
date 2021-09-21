namespace LibSignal.Protocol.Net.State
{
    using System.Collections.Generic;


    public class SessionRecord
    {

        private static readonly int ARCHIVED_STATES_MAX_LENGTH = 40;

        private SessionState sessionState = new SessionState();

        private LinkedList<SessionState> previousStates = new LinkedList<SessionState>();

        private bool fresh = false;

        public SessionRecord()
        {
            this.fresh = true;
        }

        public SessionRecord(SessionState sessionState)
        {
            this.sessionState = sessionState;
            this.fresh = false;
        }

        // Throws IOException
        public SessionRecord(byte[] serialized)
        {
            RecordStructure record = RecordStructure.parseFrom(serialized);
            this.sessionState = new SessionState(record.getCurrentSession());
            this.fresh = false;

            foreach (var previousStructure in record.getPreviousSessionsList())
            {
                previousStates.Add(new SessionState(previousStructure));
            }
        }

        public bool hasSessionState(int version, byte[] aliceBaseKey)
        {
            if (sessionState.getSessionVersion() == version && Arrays.equals(aliceBaseKey, sessionState.getAliceBaseKey()))
            {
                return true;
            }

            foreach (SessionState state in previousStates)
            {
                if (state.getSessionVersion() == version && Arrays.equals(aliceBaseKey, state.getAliceBaseKey()))
                {
                    return true;
                }
            }

            return false;
        }

        public SessionState getSessionState()
        {
            return sessionState;
        }

        public List<SessionState> getPreviousSessionStates()
        {
            return previousStates;
        }

        public void removePreviousSessionStates()
        {
            previousStates.Clear();
        }

        public bool isFresh()
        {
            return fresh;
        }

        public void archiveCurrentState()
        {
            promoteState(new SessionState());
        }

        public void promoteState(SessionState promotedState)
        {
            this.previousStates.addFirst(sessionState);
            this.sessionState = promotedState;

            if (previousStates.size() > ARCHIVED_STATES_MAX_LENGTH)
            {
                previousStates.removeLast();
            }
        }

        public void setState(SessionState sessionState)
        {
            this.sessionState = sessionState;
        }

        public byte[] serialize()
        {
            List<SessionStructure> previousStructures = new LinkedList<>();

            foreach (SessionState previousState in previousStates)
            {
                previousStructures.Add(previousState.getStructure());
            }

            RecordStructure record = RecordStructure.newBuilder().setCurrentSession(sessionState.getStructure()).addAllPreviousSessions(previousStructures).build();

            return record.toByteArray();
        }

    }

}

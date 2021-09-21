namespace LibSignal.Protocol.Net.Logging
{

    public interface SignalProtocolLogger
    {

        public static readonly int VERBOSE = 2;
        public static readonly int DEBUG = 3;
        public static readonly int INFO = 4;
        public static readonly int WARN = 5;
        public static readonly int ERROR = 6;
        public static readonly int ASSERT = 7;

        public void log(int priority, string tag, string message);
    }
}



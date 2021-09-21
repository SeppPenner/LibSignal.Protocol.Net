namespace LibSignal.Protocol.Net.State
{
    public interface SignalProtocolStore : IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore
    {
    }
}

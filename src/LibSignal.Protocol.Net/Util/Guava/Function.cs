namespace LibSignal.Protocol.Net.Util.Guava
{

    public interface Function<F, T>
    {

        T apply(F input);

        override bool equals(object object);
    }

}
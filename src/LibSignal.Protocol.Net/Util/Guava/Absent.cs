namespace LibSignal.Protocol.Net.Util.Guava
{
    using System;

    final class Absent extends Optional<Object>
    {
    static final Absent INSTANCE = new Absent();

    public override bool isPresent()
    {
        return false;
    }

    public override Object get()
    {
        throw new IllegalStateException("value is absent");
    }

    public override Object or(Object defaultValue)
    {
        return checkNotNull(defaultValue, "use orNull() instead of or(null)");
    }

    //@SuppressWarnings("unchecked") // safe covariant cast
    public override Optional<Object> or(Optional<?> secondChoice)
    {
        return (Optional)checkNotNull(secondChoice);
    }

    public override Object or(Supplier<?> supplier)
    {
        return checkNotNull(supplier.get(),
            "use orNull() instead of a Supplier that returns null");
    }

    public override Object orNull()
    {
        return null;
    }

    public override Set<Object> asSet()
    {
        return Collections.emptySet();
    }

    public override <V> Optional<V> transform(Function<? super Object, V> function)
    {
        checkNotNull(function);
        return Optional.absent();
    }

    public override bool equals(Object object)
    {
        return object == this;
    }

    public override int hashCode()
    {
        return 0x598df91c;
    }

    public override string toString()
    {
        return "Optional.absent()";
    }

    private Object readResolve()
    {
        return INSTANCE;
    }

    private static readonly long serialVersionUID = 0;
    }

}

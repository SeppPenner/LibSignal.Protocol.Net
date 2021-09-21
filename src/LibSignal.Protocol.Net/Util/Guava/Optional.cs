namespace LibSignal.Protocol.Net.Util.Guava
{
    public abstract class Optional<T> : Serializable
    {

        //@SuppressWarnings("unchecked")
        public static <T> Optional<T> absent()
        {
            return (Optional<T>)Absent.INSTANCE;
        }

        public static <T> Optional<T> of(T reference)
        {
            return new Present<T>(checkNotNull(reference));
        }

        public static <T> Optional<T> fromNullable(T nullableReference)
        {
            return (nullableReference == null)
                       ? Optional.< T > absent()
                : new Present<T>(nullableReference);
        }

        Optional() { }

        public abstract bool isPresent();

        public abstract T get();


        public abstract T or(T defaultValue);

        public abstract Optional<T> or(Optional<? extends T> secondChoice);

        public abstract T or(Supplier<? extends T> supplier);

        public abstract T orNull();

        public abstract Set<T> asSet();

        public abstract <V> Optional<V> transform(Function<? super T, V> function);

        public override abstract bool equals(object obj);

        public override abstract int hashCode();

        public override abstract string toString();


        private static readonly long serialVersionUID = 0;
    }

}


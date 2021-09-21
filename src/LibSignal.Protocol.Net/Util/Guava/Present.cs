namespace LibSignal.Protocol.Net.Util.Guava
{
    final class Present<T> : Optional<T>
    {
        private readonly T reference;

        Present(T reference)
        {
            this.reference = reference;
        }

        public override bool isPresent()
        {
            return true;
        }

        public override T get()
        {
            return reference;
        }

        public override T or(T defaultValue)
        {
            checkNotNull(defaultValue, "use orNull() instead of or(null)");
            return reference;
        }

        public override Optional<T> or(Optional<? extends T> secondChoice)
        {
            checkNotNull(secondChoice);
            return this;
        }

        public override T or(Supplier<? extends T> supplier)
        {
            checkNotNull(supplier);
            return reference;
        }

        public override T orNull()
        {
            return reference;
        }

        public override Set<T> asSet()
        {
            return Collections.singleton(reference);
        }

        public override <V> Optional<V> transform(Function<? super T, V> function)
        {
            return new Present<V>(checkNotNull(function.apply(reference),
                "Transformation function cannot return null."));
        }

        public override bool equals(object object)
        {
            if (object instanceof Present) {
                Present <?> other = (Present <?>) object;
                return reference.equals(other.reference);
            }
            return false;
        }

        public override int hashCode()
        {
            return 0x598df91c + reference.hashCode();
        }

        public override string toString()
        {
            return "Optional.of(" + reference + ")";
        }

        private static readonly long serialVersionUID = 0;
    }

}

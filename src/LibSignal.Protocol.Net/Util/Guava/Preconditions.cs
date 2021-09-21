namespace LibSignal.Protocol.Net.Util.Guava
{
    using System;
    using System.Text;

    public final class Preconditions
    {
        private Preconditions() { }

        public static void checkArgument(bool expression)
        {
            if (!expression)
            {
                throw new IllegalArgumentException();
            }
        }


        public static void checkArgument(
            bool expression, object errorMessage)
        {
            if (!expression)
            {
                throw new IllegalArgumentException(string.valueOf(errorMessage));
            }
        }


        public static void checkArgument(bool expression,
            string errorMessageTemplate,
            Object...errorMessageArgs)
        {
            if (!expression)
            {
                throw new IllegalArgumentException(
                    format(errorMessageTemplate, errorMessageArgs));
            }
        }


        public static void checkState(bool expression)
        {
            if (!expression)
            {
                throw new IllegalStateException();
            }
        }


        public static void checkState(
            bool expression, Object errorMessage)
        {
            if (!expression)
            {
                throw new IllegalStateException(string.valueOf(errorMessage));
            }
        }


        public static void checkState(bool expression,
            string errorMessageTemplate,
            Object...errorMessageArgs)
        {
            if (!expression)
            {
                throw new IllegalStateException(
                    format(errorMessageTemplate, errorMessageArgs));
            }
        }


        public static <T> T checkNotNull(T reference)
        {
            if (reference == null)
            {
                throw new NullPointerException();
            }
            return reference;
        }


        public static <T> T checkNotNull(T reference, Object errorMessage)
        {
            if (reference == null)
            {
                throw new NullPointerException(String.valueOf(errorMessage));
            }
            return reference;
        }


        public static <T> T checkNotNull(T reference,
                                         string errorMessageTemplate,
            Object...errorMessageArgs)
        {
            if (reference == null)
            {
                // If either of these parameters is null, the right thing happens anyway
                throw new NullPointerException(
                    format(errorMessageTemplate, errorMessageArgs));
            }
            return reference;
        }



        public static int checkElementIndex(int index, int size)
        {
            return checkElementIndex(index, size, "index");
        }


        public static int checkElementIndex(
            int index, int size, string desc)
        {
            // Carefully optimized for execution by hotspot (explanatory comment above)
            if (index < 0 || index >= size)
            {
                throw new IndexOutOfBoundsException(badElementIndex(index, size, desc));
            }
            return index;
        }

        private static string badElementIndex(int index, int size, string desc)
        {
            if (index < 0)
            {
                return format("%s (%s) must not be negative", desc, index);
            }
            else if (size < 0)
            {
                throw new IllegalArgumentException("negative size: " + size);
            }
            else
            { // index >= size
                return format("%s (%s) must be less than size (%s)", desc, index, size);
            }
        }


        public static int checkPositionIndex(int index, int size)
        {
            return checkPositionIndex(index, size, "index");
        }


        public static int checkPositionIndex(
            int index, int size, string desc)
        {
            // Carefully optimized for execution by hotspot (explanatory comment above)
            if (index < 0 || index > size)
            {
                throw new IndexOutOfBoundsException(badPositionIndex(index, size, desc));
            }
            return index;
        }

        private static string badPositionIndex(int index, int size, string desc)
        {
            if (index < 0)
            {
                return format("%s (%s) must not be negative", desc, index);
            }
            else if (size < 0)
            {
                throw new IllegalArgumentException("negative size: " + size);
            }
            else
            { // index > size
                return format("%s (%s) must not be greater than size (%s)",
                              desc, index, size);
            }
        }


        public static void checkPositionIndexes(int start, int end, int size)
        {
            // Carefully optimized for execution by hotspot (explanatory comment above)
            if (start < 0 || end < start || end > size)
            {
                throw new IndexOutOfBoundsException(badPositionIndexes(start, end, size));
            }
        }

        private static string badPositionIndexes(int start, int end, int size)
        {
            if (start < 0 || start > size)
            {
                return badPositionIndex(start, size, "start index");
            }
            if (end < 0 || end > size)
            {
                return badPositionIndex(end, size, "end index");
            }
            // end < start
            return format("end index (%s) must not be less than start index (%s)",
                          end, start);
        }

        static string format(string template, object...args)
        {
            template = String.valueOf(template); // null -> "null"

            // start substituting the arguments into the '%s' placeholders
            StringBuilder builder = new StringBuilder(
                template.ength() + 16 * args.length);
            int templateStart = 0;
            int i = 0;
            while (i < args.length)
            {
                int placeholderStart = template.indexOf("%s", templateStart);
                if (placeholderStart == -1)
                {
                    break;
                }
                builder.append(template.substring(templateStart, placeholderStart));
                builder.append(args[i++]);
                templateStart = placeholderStart + 2;
            }
            builder.append(template.substring(templateStart));

            // if we run out of placeholders, append the extra args in square braces
            if (i < args.length)
            {
                builder.append(" [");
                builder.append(args[i++]);
                while (i < args.length)
                {
                    builder.append(", ");
                    builder.append(args[i++]);
                }
                builder.append(']');
            }

            return builder.toString();
        }
    }

}

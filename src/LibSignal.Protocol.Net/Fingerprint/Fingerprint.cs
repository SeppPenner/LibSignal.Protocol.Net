namespace LibSignal.Protocol.Net.Fingerprint
{
    public class Fingerprint
    {

        private readonly DisplayableFingerprint displayableFingerprint;
        private readonly ScannableFingerprint scannableFingerprint;

        public Fingerprint(DisplayableFingerprint displayableFingerprint,
                           ScannableFingerprint scannableFingerprint)
        {
            this.displayableFingerprint = displayableFingerprint;
            this.scannableFingerprint = scannableFingerprint;
        }

        /**
         * @return A text fingerprint that can be displayed and compared remotely.
         */
        public DisplayableFingerprint getDisplayableFingerprint()
        {
            return displayableFingerprint;
        }

        /**
         * @return A scannable fingerprint that can be scanned and compared locally.
         */
        public ScannableFingerprint getScannableFingerprint()
        {
            return scannableFingerprint;
        }
    }
}

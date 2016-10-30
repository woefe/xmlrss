package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public class WPProvider extends Provider{

    public WPProvider() {
        super("WP", 0.1, "WP Provider (implements Redactable Signature Schemes, Accumulators)");
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                /*
                 * Signature engines
                 */
                put("RedactableSignature.RSSwithPSAccumulator", "de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss.PSRedactableSignature$RSSwithPSA");
                put("Alg.Alias.RedactableSignature.RSSwithACC", "RSSwithPSAccumulator");
                put("Alg.Alias.RedactableSignature.RSSwithPSA", "RSSwithPSAccumulator");

                /*
                 *  Key Pair Generator engines
                 */
                put("KeyPairGenerator.PSRSS", "de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss.PSRSSKeyPairGenerator");

                /*
                 * Accumulator engines
                 */
                put("Accumulator.PSA", "de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss.PSAccumulator");


                return null;
            }
        });
    }
}

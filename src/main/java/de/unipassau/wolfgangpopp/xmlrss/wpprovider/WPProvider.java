package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public class WPProvider extends Provider{

    public WPProvider() {
        // TODO: 10/26/16 better description
        super("WP", 0.1, "Redactable Signature Schemes; Accumulators");
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                /*
                 * Signature engines
                 */
                put("RedactableSignature.TestDummy", "de.unipassau.wolfgangpopp.xmlrss.TestDummy");
                //put("RedactableSignature.RSARedactableSignature", "de.unipassau.wolfgangpopp.RSARedactableSignature");
                //put("RedactableSignature.ECDSARedactableSignature", "sun.security.provider.DSA");
                //put("Alg.Alias.RedactableSignature.RSSwithACC", "SHA1withDSA");

                /*
                 *  Key Pair Generator engines
                put("KeyPairGenerator.RSS", "sun.security.provider.DSAKeyPairGenerator");
                 */

                /*
                 * Accumulator engines
                put("MessageDigest.MD5", "sun.security.provider.MD5");
                put("MessageDigest.SHA", "sun.security.provider.SHA");
                 */


                return null;
            }
        });
    }
}

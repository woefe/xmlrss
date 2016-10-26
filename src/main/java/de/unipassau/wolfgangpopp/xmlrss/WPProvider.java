package de.unipassau.wolfgangpopp.xmlrss;

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
                put("RedactableSignature.RSARedactableSignature", "de.unipassau.wolfgangpopp.RSARedactableSignature");
                put("RedactableSignature.ECDSARedactableSignature", "sun.security.provider.DSA");
                put("Alg.Alias.RedactableSignature.RSSwithACC", "SHA1withDSA");

                /*
                 *  Key Pair Generator engines
                 */
                put("KeyPairGenerator.DSA", "sun.security.provider.DSAKeyPairGenerator");
                put("Alg.Alias.KeyPairGenerator.OID.1.2.840.10040.4.1", "DSA");
                put("Alg.Alias.KeyPairGenerator.1.2.840.10040.4.1", "DSA");
                put("Alg.Alias.KeyPairGenerator.1.3.14.3.2.12", "DSA");

                /*
                 * Digest engines
                 */
                put("MessageDigest.MD5", "sun.security.provider.MD5");
                put("MessageDigest.SHA", "sun.security.provider.SHA");

                put("Alg.Alias.MessageDigest.SHA-1", "SHA");
                put("Alg.Alias.MessageDigest.SHA1", "SHA");

                return null;
            }
        });
    }
}

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 * @author Wolfgang Popp
 */
public class PSRSSPublicKey extends PSRSSKey implements PublicKey{
    public PSRSSPublicKey(BigInteger key) {
        super(key);
    }
}

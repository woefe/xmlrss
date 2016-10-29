package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import java.math.BigInteger;
import java.security.PrivateKey;

/**
 * @author Wolfgang Popp
 */
public class PSRSSPrivateKey extends PSRSSKey implements PrivateKey {

    public PSRSSPrivateKey(BigInteger key) {
        super(key);
    }

}

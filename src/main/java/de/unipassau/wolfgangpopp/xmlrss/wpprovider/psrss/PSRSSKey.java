package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import java.math.BigInteger;
import java.security.Key;

/**
 * @author Wolfgang Popp
 */
public abstract class PSRSSKey implements Key {
    private static final String ALGORITHM = "RSS";
    private BigInteger key = null;

    public PSRSSKey(BigInteger key) {
        this.key = key;
    }

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    public BigInteger getKey() {
        return key;
    }
}

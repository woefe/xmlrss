package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import java.util.Arrays;

/**
 * @author Wolfgang Popp
 */
class PSMessagePart {
    private final byte[] array;

    public PSMessagePart(byte[] array) {
        this.array = array;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PSMessagePart part = (PSMessagePart) o;

        return Arrays.equals(array, part.array);

    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(array);
    }

    public byte[] getArray() {
        return array;
    }
}

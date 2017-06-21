/*
 * XMLRSS - A Java Crypto Provider for Redactable Signatures and their
 * XML Signature encoding.
 *
 * Copyright (c) 2017 Wolfgang Popp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils;

import java.util.Arrays;

/**
 * The <code>ByteArray</code> class is a wrapper class for byte arrays. This class is needed to use byte arrays in
 * collections. The default implementation of equals() of an byte[] array only checks for object identity, which is not
 * sufficient when using byte arrays in collections.
 *
 * @author Wolfgang Popp
 */
public class ByteArray implements Comparable<ByteArray> {
    private final byte[] array;

    /**
     * Constructs a new ByteArray that wraps the given byte[] array.
     *
     * @param array the array wrapped by this ByteArray
     */
    public ByteArray(byte[] array) {
        this.array = array;
    }

    /**
     * Checks if this ByteArray is equal to another object. This is true if the other object is also a ByteArray and the
     * two arrays have the same length, and all corresponding pairs of elements in the two arrays are equal.
     *
     * @param o the other object
     * @return true if the other object is a ByteArray and the underlying byte[] arrays are equal
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        ByteArray part = (ByteArray) o;

        return Arrays.equals(array, part.array);
    }

    /**
     * Returns a hash code as calculated by the {@link Arrays#hashCode(byte[])} method.
     *
     * @return a hash code
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(array);
    }

    /**
     * Returns the underlying, wrapped byte[] array.
     *
     * @return the underlying, wrapped byte[] array.
     */
    public byte[] getArray() {
        return array;
    }

    /**
     * Compares this byte array to another byte array.
     *
     * @param o the other byte array
     * @return zero, if both arrays are equal. A negative integer if the difference of the first pair of bytes which are
     * different is negative or the length of this array is smaller than the length of the other array. A positive
     * integer otherwise.
     */
    @Override
    public int compareTo(ByteArray o) {
        int len = Math.min(array.length, o.array.length);

        for (int i = 0; i < len; i++) {
            if (array[i] != o.array[i]) {
                return array[i] - o.array[i];
            }
        }

        return array.length - o.array.length;
    }

    @Override
    public String toString() {
        return Arrays.toString(array);
    }

    /**
     * Concatenates this ByteArray with another byte array. The returned byte array has the length of
     * <code>getArray().length + bytes.getArray().length</code> and this array is located in the front of the returned
     * array. E.g. concatenating [1,2,3] with [4,5,6] results in [1,2,3,4,5,6]
     *
     * @param bytes the byte array to concatenate
     * @return this byte array concatenated with the given byte array
     */
    public ByteArray concat(ByteArray bytes) {
        return concat(bytes.getArray());
    }

    /**
     * Concatenates this ByteArray with another byte array. The returned byte array has the length of
     * <code>getArray().length + bytes.getArray().length</code> and this array is located in the front of the returned
     * array. E.g. concatenating [1,2,3] with [4,5,6] results in [1,2,3,4,5,6]
     *
     * @param other the byte array to concatenate
     * @return this byte array concatenated with the given byte array
     */
    public ByteArray concat(byte[] other) {
        byte[] thisConcatOther = new byte[other.length + this.array.length];
        System.arraycopy(this.array, 0, thisConcatOther, 0, this.array.length);
        System.arraycopy(other, 0, thisConcatOther, array.length, other.length);

        return new ByteArray(thisConcatOther);
    }
}

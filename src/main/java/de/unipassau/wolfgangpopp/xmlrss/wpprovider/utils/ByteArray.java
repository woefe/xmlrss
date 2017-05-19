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
 * @author Wolfgang Popp
 */
public class ByteArray implements Comparable<ByteArray> {
    private final byte[] array;

    public ByteArray(byte[] array) {
        this.array = array;
    }

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

    @Override
    public int hashCode() {
        return Arrays.hashCode(array);
    }

    public byte[] getArray() {
        return array;
    }

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

    public ByteArray concat(ByteArray bytes) {
        return concat(bytes.getArray());
    }

    public ByteArray concat(byte[] other) {
        byte[] thisConcatOther = new byte[other.length + this.array.length];
        System.arraycopy(this.array, 0, thisConcatOther, 0, this.array.length);
        System.arraycopy(other, 0, thisConcatOther, array.length, other.length);

        return new ByteArray(thisConcatOther);
    }
}

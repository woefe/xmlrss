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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;

/**
 * The <code>Identifier</code> class provides means to identify elements in a set as well as elements of a list.
 * <p>
 * When elements within a list are removed, the indices change. To make sure the elements are actually located at the
 * expected positions the Identifier requires to set both the index and the expected element.
 *
 * @author Wolfgang Popp
 */
public class Identifier {
    private final ByteArray bytes;
    private int position = -1;

    /**
     * Constructs a new identifier suitable to identify an element in a list.
     *
     * @param bytes    the bytes expected at the given position
     * @param position the position of the expected bytes
     */
    public Identifier(ByteArray bytes, int position) {
        this.bytes = bytes;
        this.position = position;
    }

    /**
     * Constructs a new identifier suitable to identify an element in a list.
     *
     * @param bytes    the bytes expected at the given position
     * @param position the position of the expected bytes
     */
    public Identifier(byte[] bytes, int position) {
        this.bytes = new ByteArray(bytes);
        this.position = position;
    }

    /**
     * Constructs a new identifier suitable to identify an element in a set.
     *
     * @param bytes the element in a set
     */
    public Identifier(byte[] bytes) {
        this.bytes = new ByteArray(bytes);
    }

    /**
     * Constructs a new identifier suitable to identify an element in a set.
     *
     * @param bytes the element in a set
     */
    public Identifier(ByteArray bytes) {
        this.bytes = bytes;
    }

    /**
     * Returns the identified element.
     *
     * @return the identified element
     */
    public ByteArray getByteArray() {
        return bytes;
    }

    /**
     * Returns the identified element.
     *
     * @return the identified element
     */
    public byte[] getBytes() {
        return getByteArray().getArray();
    }

    /**
     * Returns the position of the identified element
     *
     * @return the position or -1 if the identifier is not suitable to identify an element in a list
     */
    public int getPosition() {
        return position;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Identifier that = (Identifier) o;

        return getPosition() == that.getPosition()
                && (getByteArray() != null ? getByteArray().equals(that.getByteArray()) : that.getByteArray() == null);
    }

    @Override
    public int hashCode() {
        int result = getByteArray() != null ? getByteArray().hashCode() : 0;
        result = 31 * result + getPosition();
        return result;
    }
}

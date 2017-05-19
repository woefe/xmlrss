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
 * @author Wolfgang Popp
 */
public class Identifier {
    private final ByteArray bytes;
    private int position = -1;

    public Identifier(ByteArray bytes, int position) {
        this.bytes = bytes;
        this.position = position;
    }

    public Identifier(byte[] bytes, int position) {
        this.bytes = new ByteArray(bytes);
        this.position = position;
    }

    public Identifier(byte[] bytes) {
        this.bytes = new ByteArray(bytes);
    }

    public Identifier(ByteArray bytes) {
        this.bytes = bytes;
    }

    public ByteArray getByteArray() {
        return bytes;
    }

    public byte[] getBytes() {
        return getByteArray().getArray();
    }

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

/*
 * XMLRSS - A Java Crypto Provider for Redactable Signatures and their
 * XML Signature encoding.
 *
 * Copyright (c) 2016 Wolfgang Popp
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

/**
 * The <code>SignatureOutput</code> is a common interface for all signature output implementations. The signature output
 * contains both the message and the corresponding signature.
 *
 * @author Wolfgang Popp
 */
public interface SignatureOutput {

    /**
     * Checks if this signature output contains the given message part.
     *
     * @param part the message part that is checked to be part of this output
     * @return true if this signature output contains the given message part, false otherwise
     */
    boolean contains(byte[] part);

    /**
     * Checks if the given identifier identifies any element in this signature output.
     *
     * @param identifier the identifier to check
     * @return true if the given identifier identifies an element in this signature output, false otherwise
     */
    boolean contains(Identifier identifier);

    /**
     * Checks if all given parts are contained in this signature output.
     *
     * @param parts the parts that are checked be part of this output
     * @return true if this signature output contains all given parts, false otherwise
     */
    boolean containsAll(byte[]... parts);

    /**
     * Checks if the part that is identified by the given identifier is redactable.
     *
     * @param identifier the identifier
     * @return true if the identified part is redactable, false otherwise
     */
    boolean isRedactable(Identifier identifier);

    /**
     * Returns the message part that is identified by the given identifier.
     *
     * @param identifier the identifier
     * @return the message part identified by the given identifier
     */
    byte[] getMessagePart(Identifier identifier);

    /**
     * Returns the proof of the part identified by the given identifier.
     *
     * @param identifier the identifier
     * @return the proof of the part identified by the given identifier
     */
    byte[] getProof(Identifier identifier);

    /**
     * Returns the number of message parts of this signature output.
     *
     * @return the size of this signature output
     */
    int size();
}

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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml;

import java.security.GeneralSecurityException;

/**
 * The <code>RedactableXMLSignatureException</code> is the general Exception for redactable signature implementations.
 *
 * @author Wolfgang Popp
 */
public class RedactableXMLSignatureException extends GeneralSecurityException {

    /**
     * Constructs a new RedactableXMLSignatureException with the given detail message.
     *
     * @param message the detail message
     */
    public RedactableXMLSignatureException(String message) {
        super(message);
    }

    /**
     * Constructs a new RedactableXMLSignatureException with the given detail message and cause.
     *
     * @param message the detail message
     * @param cause   the cause of this exception
     */
    public RedactableXMLSignatureException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new RedactableXMLSignatureException with the given cause.
     *
     * @param cause the cause of this exception
     */
    public RedactableXMLSignatureException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new RedactebleXMLSignatureException without a detail message
     */
    public RedactableXMLSignatureException() {
    }
}

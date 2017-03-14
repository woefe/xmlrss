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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * @author Wolfgang Popp
 */
class Dereferencer {
    private static final String XPOINTER_BEGIN = "#xpointer(id(";
    private static final int XPOINTER_BEGIN_LEN = XPOINTER_BEGIN.length();
    private static final String XPOINTER_END = "))";
    private static final int XPOINTER_END_LEN = XPOINTER_END.length();

    private static boolean isRootNodeXPointer(String xPointer) {
        return xPointer.equals("#xpointer(/)");
    }

    private static boolean isIdXPointer(String xPointer) {
        return (xPointer.startsWith(XPOINTER_BEGIN + "'") && xPointer.endsWith("'" + XPOINTER_END))
                || (xPointer.startsWith(XPOINTER_BEGIN + "\"") && xPointer.endsWith("\"" + XPOINTER_END));
    }

    private static String extractId(String xPointer) {
        return xPointer.substring(XPOINTER_BEGIN_LEN + 1, xPointer.length() - XPOINTER_END_LEN - 1);
    }

    public static Node dereference(String xPointer, Node root) throws RedactableXMLSignatureException {
        if (xPointer == null || xPointer.length() == 0 || isRootNodeXPointer(xPointer)) {
            return root;
        } else if (isIdXPointer(xPointer)) {
            Document doc = root.getOwnerDocument();
            String id = extractId(xPointer);
            Element element = doc.getElementById(id);
            if (element == null) {
                throw new RedactableXMLSignatureException("Cannot resolve element with ID " + id);
            }
            return element;
        }

        throw new RedactableXMLSignatureException("unsupported URI");
    }
}

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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.namespace.QName;
import javax.xml.transform.dom.DOMResult;

/**
 * @author Wolfgang Popp
 */
public class XMLUtils {
    public static Node checkNode(Node node, String expectedNodeName) throws RedactableXMLSignatureException {
        if (node == null || !expectedNodeName.equals(node.getNodeName())) {
            throw new RedactableXMLSignatureException("Cannot find expected node '" + expectedNodeName + "'");
        }

        return node;
    }

    public static Document getOwnerDocument(Node node) {
        if (node.getNodeType() == Node.DOCUMENT_NODE) {
            return (Document) node;
        }
        return node.getOwnerDocument();
    }

    public static Node getSignatureNode(Node root) throws RedactableXMLSignatureException {
        Document doc = getOwnerDocument(root);
        return checkNode(doc.getElementsByTagNameNS(RedactableXMLSignature.XML_NAMESPACE, "Signature").item(0),
                "Signature");
    }
}

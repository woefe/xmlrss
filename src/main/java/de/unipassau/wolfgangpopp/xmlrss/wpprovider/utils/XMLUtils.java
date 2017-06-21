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
 * The <code>XMLUtils</code> class contains helper functions for XML operations.
 *
 * @author Wolfgang Popp
 */
public class XMLUtils {

    /**
     * Checks whether the given node has the expected name. This function throws an exception if the node does not have
     * the expected name
     *
     * @param node             the node to check
     * @param expectedNodeName the expected name of the node
     * @return the given node unmodified
     * @throws RedactableXMLSignatureException if the given node does not have the expected name
     */
    public static Node checkNode(Node node, String expectedNodeName) throws RedactableXMLSignatureException {
        if (node == null || !expectedNodeName.equals(node.getNodeName())) {
            throw new RedactableXMLSignatureException("Cannot find expected node '" + expectedNodeName + "'");
        }

        return node;
    }

    /**
     * Returns the document of a given node.
     *
     * @param node the node
     * @return the document of the given node
     */
    public static Document getOwnerDocument(Node node) {
        if (node.getNodeType() == Node.DOCUMENT_NODE) {
            return (Document) node;
        }
        return node.getOwnerDocument();
    }

    /**
     * Retrieves the signature node of the given root node.
     *
     * @param root the root node of an XML document
     * @return the signature node
     * @throws RedactableXMLSignatureException if the Signature node could not be found
     */
    public static Node getSignatureNode(Node root) throws RedactableXMLSignatureException {
        Document doc = getOwnerDocument(root);
        return checkNode(doc.getElementsByTagNameNS(RedactableXMLSignature.XML_NAMESPACE, "Signature").item(0),
                "Signature");
    }
}

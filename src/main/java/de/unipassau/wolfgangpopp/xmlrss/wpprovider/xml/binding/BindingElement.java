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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * @author Wolfgang Popp
 */
public abstract class BindingElement<T> {
    public String getTagName() {
        return getClass().getSimpleName();
    }

    public Element createThisElement(Document document) {
        return document.createElementNS(RedactableXMLSignature.XML_NAMESPACE, getTagName());
    }

    public Element createElement(Document document, String name) {
        return document.createElementNS(RedactableXMLSignature.XML_NAMESPACE, name);
    }

    public Node checkThisNode(Node node) throws RedactableXMLSignatureException {
        return XMLUtils.checkNode(node, getTagName());
    }

    public abstract T unmarshall(Node node) throws RedactableXMLSignatureException;

    public abstract Node marshall(Document document);

}

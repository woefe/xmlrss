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
 * The BindingElement is the abstract base class for all classes that bind Java objects to a corresponding XML element.
 *
 * @author Wolfgang Popp
 */
public abstract class BindingElement<T extends BindingElement> {

    /**
     * Returns the name of the corresponding XML element tags.
     * <p>
     * The default implementation returns the simple name of the class. Implementors can override this method if this is
     * not the desired behavior.
     *
     * @return the name of XML tags that this element represents
     */
    public String getTagName() {
        return getClass().getSimpleName();
    }

    /**
     * Creates a new DOM element with the name returned by {@link #getTagName()}.
     *
     * @param document the DOM document that is used to create the element
     * @return a new DOM element with tag name as returned by {@link #getTagName()}
     */
    public Element createThisElement(Document document) {
        return createElement(document, getTagName());
    }

    /**
     * Creates a new DOM element with the specified name.
     *
     * @param document the DOM document that is used to create the element
     * @param name     the name of the newly create element
     * @return a new DOM element with the specified name
     */
    public Element createElement(Document document, String name) {
        return document.createElementNS(RedactableXMLSignature.XML_NAMESPACE, name);
    }

    /**
     * Checks if the name of the given node equals {@link #getTagName()}.
     *
     * @param node the node to check
     * @return the unmodified node that was given as parameter
     * @throws RedactableXMLSignatureException if the name of the node is not equal to the name returned by
     *                                         {@link #getTagName()}
     */
    public Node checkThisNode(Node node) throws RedactableXMLSignatureException {
        return checkNode(node, getTagName());
    }

    /**
     * Checks if the given name equals the name of the given node.
     *
     * @param node         the node to check
     * @param expectedName the expected name of the node
     * @return the unmodified node that was given as parameter
     * @throws RedactableXMLSignatureException if the name of the node is not equal to the expected name
     */
    public Node checkNode(Node node, String expectedName) throws RedactableXMLSignatureException {
        return XMLUtils.checkNode(node, expectedName);
    }

    /**
     * Unmarshalls the given node to a binding object.
     * <p>
     * Implementors should always use {@link #checkThisNode(Node)} and {@link #checkNode(Node, String)} to make sure
     * the children of the given node are actually the expected nodes.
     *
     * @param node the DOM node to unmarshall
     * @return the unmarshalled binding object (usually by returning <code>this</code>)
     * @throws RedactableXMLSignatureException if the given node cannot be unmarshalled. E.g. because the node is
     *                                         missing attributes.
     */
    public abstract T unmarshall(Node node) throws RedactableXMLSignatureException;

    /**
     * Marshalls this binding element to a DOM node.
     * <p>
     * Implementors must make sure to marshall all attributes necessary to restore the node later.
     *
     * @param document the document used to create new nodes
     * @return a DOM node representation of this binding element
     */
    public abstract Node marshall(Document document);

}

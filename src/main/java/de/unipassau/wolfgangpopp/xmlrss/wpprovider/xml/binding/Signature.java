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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

/**
 * The Signature class is responsible for marshalling and unmarshalling the <code>Signature</code> element of the
 * redactable signature XML encoding. The signature element is the root element of the XML encoding. The redactable XML
 * signature allows different implementations to use their own implementations of Proof and Signature value classes.
 * Those classes are denoted by the type parameters <code>S</code> and <code>P</code>.
 * <p>
 * The XSD Schema of the signature element is defined as following
 * <pre>
 * {@code
 * <element name="Signature">
 *     <complexType>
 *         <sequence>
 *             <element ref="drs:SignatureInfo"/>
 *             <element ref="drs:References"/>
 *             <element name="SignatureValue" type="anyType"/>
 *             <element name="KeyInfo" type="anyType" minOccurs="0" maxOccurs="1"/>
 *         </sequence>
 *     </complexType>
 * </element>
 * }
 * </pre>
 *
 * @author Wolfgang Popp
 */
public final class Signature<S extends SignatureValue, P extends Proof> extends BindingElement<Signature> {

    private final Class<P> proofClass;
    private final Class<S> signatureValueClass;
    private List<Reference<P>> references = new ArrayList<>();
    private S signatureValue;
    private SignatureInfo signatureInfo;

    /**
     * Constructs a new signature object whose signature value and proofs are the given classes.
     *
     * @param proofClass          the class of the used proof (same as the type parameter P)
     * @param signatureValueClass the class of the used signature value (same as the type parameter S)
     */
    public Signature(Class<P> proofClass, Class<S> signatureValueClass) {
        this.proofClass = proofClass;
        this.signatureValueClass = signatureValueClass;
    }

    /**
     * Returns the signature info element.
     *
     * @return the signature info element
     */
    public SignatureInfo getSignatureInfo() {
        return signatureInfo;
    }

    /**
     * Returns the list of references.
     *
     * @return the list of references
     */
    public List<Reference<P>> getReferences() {
        return references;
    }

    /**
     * Returns the signature value.
     *
     * @return the signature value.
     */
    public S getSignatureValue() {
        return signatureValue;
    }

    /**
     * Sets the signature info.
     *
     * @param signatureInfo the signature info
     * @return this signature object
     */
    public Signature setSignatureInfo(SignatureInfo signatureInfo) {
        this.signatureInfo = signatureInfo;
        return this;
    }

    /**
     * Sets the references.
     *
     * @param reference the references
     * @return this signature object
     */
    public Signature addReference(Reference<P> reference) {
        references.add(reference);
        return this;
    }

    /**
     * Sets the signature value.
     *
     * @param signatureValue the signature value
     * @return this signature object
     */
    public Signature setSignatureValue(S signatureValue) {
        this.signatureValue = signatureValue;
        return this;
    }

    @SuppressWarnings("unchecked")
    @Override
    public Signature<S, P> unmarshall(Node node) throws RedactableXMLSignatureException {
        Node signature = checkThisNode(node);
        Node signatureInfo = signature.getFirstChild();
        this.signatureInfo = new SignatureInfo().unmarshall(signatureInfo);

        Node referencesNode = signatureInfo.getNextSibling();
        NodeList references = referencesNode.getChildNodes();
        this.references.clear();
        for (int i = 0; i < references.getLength(); i++) {
            this.references.add(new Reference<>(proofClass).unmarshall(references.item(i)));
        }

        Node signatureValue = referencesNode.getNextSibling();
        try {
            this.signatureValue = (S) signatureValueClass.newInstance().unmarshall(signatureValue);
        } catch (InstantiationException | IllegalAccessException e) {
            throw new RedactableXMLSignatureException(signatureValueClass.getName() +
                    " has no public default constructor", e);
        }
        return this;
    }

    @Override
    public Node marshall(Document document) {
        Element element = createThisElement(document);
        element.appendChild(signatureInfo.marshall(document));
        Node references = element.appendChild(createElement(document, "References"));
        for (Reference reference : this.references) {
            references.appendChild(reference.marshall(document));
        }

        element.appendChild(references);
        element.appendChild(signatureValue.marshall(document));
        element.setAttribute("xmlns", RedactableXMLSignature.XML_NAMESPACE);
        return element;
    }
}

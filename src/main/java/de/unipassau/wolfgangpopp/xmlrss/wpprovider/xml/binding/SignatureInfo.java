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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils.checkNode;

/**
 * The SignatureInfo class is responsible for marshalling and unmarshalling the <code>SignatureInfo</code> element of
 * the redactable signature XML encoding. The SignatureInfo element states the used canonicalization method and the
 * redactable signature algorithm.
 * <p>
 * The XSD Schema of the signature info is defined as following
 * <pre>
 * {@code
 * <element name="SignatureInfo">
 *     <complexType>
 *         <sequence>
 *             <element ref="drs:CanonicalizationMethod"/>
 *             <element ref="drs:RedactableSignatureAlgorithm"/>
 *         </sequence>
 *     </complexType>
 * </element>
 * }
 * </pre>
 *
 * @author Wolfgang Popp
 */
public class SignatureInfo extends BindingElement<SignatureInfo> {

    private static final String REDACTABLE_SIGNATURE_ALGORITHM = "RedactableSignatureAlgorithm";
    private static final String CANONICALIZATION_METHOD = "CanonicalizationMethod";
    private String canonicalizationMethod;
    private String redactableSignatureAlgorithm;

    /**
     * Constructs a new and empty SignatureInfo.
     * <p>
     * The attributes of this signature info are initialized when calling the {@link #unmarshall(Node)} method.
     */
    public SignatureInfo() {
    }

    /**
     * Constructs a new SignatureInfo with the given canonicalization method and signature algorithm.
     *
     * @param canonicalizationMethod    the used canonicalization method
     * @param redactableSignatureMethod the use redactable signature algorithm
     */
    public SignatureInfo(String canonicalizationMethod, String redactableSignatureMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
        this.redactableSignatureAlgorithm = redactableSignatureMethod;
    }

    /**
     * Returns the canonicalization method used in this redactable xml signature.
     *
     * @return the canonicalization method
     */
    public String getCanonicalizationMethod() {
        return canonicalizationMethod;
    }

    /**
     * Returns the redactable signature algorithm used in this redactable xml signature.
     *
     * @return the redactable signature algorithm
     */
    public String getRedactableSignatureMethod() {
        return redactableSignatureAlgorithm;
    }

    @Override
    public SignatureInfo unmarshall(Node node) throws RedactableXMLSignatureException {
        Node signatureInfo = checkThisNode(node);
        Node canonicalizationMethod = checkNode(signatureInfo.getFirstChild(), CANONICALIZATION_METHOD);
        this.canonicalizationMethod = canonicalizationMethod.getTextContent();

        Node redactableSignatureAlgorithm = checkNode(canonicalizationMethod.getNextSibling(),
                REDACTABLE_SIGNATURE_ALGORITHM);
        this.redactableSignatureAlgorithm = redactableSignatureAlgorithm.getTextContent();

        return this;
    }

    @Override
    public Node marshall(Document document) {
        Element signatureInfo = createThisElement(document);
        Element canonicalizationMethod = createElement(document, CANONICALIZATION_METHOD);
        Element redactableSignatureAlgorithm = createElement(document, REDACTABLE_SIGNATURE_ALGORITHM);

        canonicalizationMethod.setAttribute("Algorithm", this.canonicalizationMethod);
        redactableSignatureAlgorithm.setAttribute("Algorithm", this.redactableSignatureAlgorithm);

        signatureInfo.appendChild(canonicalizationMethod);
        signatureInfo.appendChild(redactableSignatureAlgorithm);

        return signatureInfo;
    }
}

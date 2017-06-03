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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.xml;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.SignatureValue;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Base64;

/**
 * @author Wolfgang Popp
 */
public class GSSignatureValue extends SignatureValue {
    private String dsigValue;
    private String accumulatorValue;

    public GSSignatureValue() {
    }

    public GSSignatureValue(byte[] dsigValue, byte[] accumulatorValue) {
        Base64.Encoder encoder = Base64.getEncoder();
        this.dsigValue = encoder.encodeToString(dsigValue);
        this.accumulatorValue = encoder.encodeToString(accumulatorValue);
    }

    public byte[] getDSigValue() {
        return Base64.getDecoder().decode(dsigValue);
    }

    public byte[] getAccumulatorValue() {
        return Base64.getDecoder().decode(accumulatorValue);
    }

    @Override
    public GSSignatureValue unmarshall(Node node) throws RedactableXMLSignatureException {
        Node signatureValue = checkThisNode(node);
        Node dSigValue = checkNode(signatureValue.getFirstChild(), "DSigValue");
        this.dsigValue = dSigValue.getTextContent();

        Node accumulatorValue = checkNode(dSigValue.getNextSibling(), "AccumulatorValue");
        this.accumulatorValue = accumulatorValue.getTextContent();

        return this;
    }

    @Override
    public Node marshall(Document document) {
        Element signatureValue = createThisElement(document);

        Element tag = document.createElement("DSigValue");
        tag.setTextContent(this.dsigValue);
        signatureValue.appendChild(tag);

        Element accumulatorValue = document.createElement("AccumulatorValue");
        accumulatorValue.setTextContent(this.accumulatorValue);
        signatureValue.appendChild(accumulatorValue);

        return signatureValue;
    }
}

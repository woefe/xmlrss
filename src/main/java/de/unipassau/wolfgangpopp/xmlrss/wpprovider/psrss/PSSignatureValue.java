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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.SignatureValue;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Base64;

import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils.checkNode;

/**
 * @author Wolfgang Popp
 */
public class PSSignatureValue extends SignatureValue {
    private final Base64.Encoder encoder = Base64.getEncoder();
    private final Base64.Decoder decoder = Base64.getDecoder();
    private String tag;
    private String proofOfTag;
    private String accumulator;

    public PSSignatureValue() {
    }

    public PSSignatureValue(byte[] tag, byte[] proofOfTag, byte[] accumulator) {
        this.tag = encoder.encodeToString(tag);
        this.proofOfTag = encoder.encodeToString(proofOfTag);
        this.accumulator = encoder.encodeToString(accumulator);
    }

    public PSSignatureValue(PSSignatureOutput output) {
        this(output.getTag(), output.getProofOfTag(), output.getAccumulator());
    }

    public byte[] getTag() {
        return decoder.decode(tag);
    }

    public byte[] getProofOfTag() {
        return decoder.decode(proofOfTag);
    }

    public byte[] getAccumulator() {
        return decoder.decode(accumulator);
    }


    @Override
    public PSSignatureValue unmarshall(Node node) throws RedactableXMLSignatureException {
        Node signatureValue = checkThisNode(node);
        Node tag = checkNode(signatureValue.getFirstChild(), "Tag");
        this.tag = tag.getTextContent();

        Node proofOfTag = checkNode(tag.getNextSibling(), "ProofOfTag");
        this.proofOfTag = proofOfTag.getTextContent();

        Node accumulatorValue = checkNode(proofOfTag.getNextSibling(), "AccumulatorValue");
        this.accumulator = accumulatorValue.getTextContent();

        return this;
    }

    @Override
    public Node marshall(Document document) {
        Element signatureValue = createThisElement(document);

        Element tag = document.createElement("Tag");
        tag.setTextContent(this.tag);
        signatureValue.appendChild(tag);

        Element proofOfTag = document.createElement("ProofOfTag");
        proofOfTag.setTextContent(this.proofOfTag);
        signatureValue.appendChild(proofOfTag);

        Element accumulatorValue = document.createElement("AccumulatorValue");
        accumulatorValue.setTextContent(this.accumulator);
        signatureValue.appendChild(accumulatorValue);

        return signatureValue;
    }
}

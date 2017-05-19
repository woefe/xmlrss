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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.SignatureValue;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.Base64;

/**
 * @author Wolfgang Popp
 */
@XmlRootElement(name = "SignatureValue", namespace = RedactableXMLSignature.XML_NAMESPACE)
@XmlType(propOrder = {"tag", "proofOfTag", "accumulator"})
public class PSSignatureValue implements SignatureValue {

    @XmlElement(name = "Tag", namespace = RedactableXMLSignature.XML_NAMESPACE)
    private String tag;

    @XmlElement(name = "ProofOfTag", namespace = RedactableXMLSignature.XML_NAMESPACE)
    private String proofOfTag;

    @XmlElement(name = "Accumulator", namespace = RedactableXMLSignature.XML_NAMESPACE)
    private String accumulator;

    private final Base64.Encoder encoder = Base64.getEncoder();
    private final Base64.Decoder decoder = Base64.getDecoder();

    private PSSignatureValue() {
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
}

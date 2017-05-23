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

import java.util.Base64;

import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils.checkNode;

/**
 * @author Wolfgang Popp
 */
public class SimpleProof extends Proof {
    private String proof;

    public SimpleProof() {
    }

    public SimpleProof(byte[] proof) {
        this.proof = Base64.getEncoder().encodeToString(proof);
    }

    public byte[] getBytes() {
        return Base64.getDecoder().decode(proof);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        SimpleProof gsProof = (SimpleProof) o;

        return proof != null ? proof.equals(gsProof.proof) : gsProof.proof == null;
    }

    @Override
    public int hashCode() {
        return proof != null ? proof.hashCode() : 0;
    }

    @Override
    public Proof unmarshall(Node node) throws RedactableXMLSignatureException {
        Node proof = checkThisNode(node);
        Node data = checkNode(proof.getFirstChild(), "Data");
        this.proof = data.getTextContent();
        return this;
    }

    @Override
    public Node marshall(Document document) {
        Element simpleProof = createThisElement(document);
        Element data = createElement(document, "Data");
        data.setTextContent(proof);
        simpleProof.appendChild(data);
        return simpleProof;
    }
}

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

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author Wolfgang Popp
 */
@XmlRootElement(name = "SignatureInfo")
@XmlType(propOrder = {"canonicalizationMethod", "redactableSignatureAlgorithm"})
public class SignatureInfo {

    @XmlElement(name = "CanonicalizationMethod")
    private AlgorithmElement canonicalizationMethod;

    @XmlElement(name = "RedactableSignatureAlgorithm")
    private AlgorithmElement redactableSignatureAlgorithm;

    private SignatureInfo() {
    }

    public SignatureInfo(String canonicalizationMethod, String redactableSignatureMethod) {
        this.canonicalizationMethod = new AlgorithmElement(canonicalizationMethod);
        this.redactableSignatureAlgorithm = new AlgorithmElement(redactableSignatureMethod);
    }

    public String getCanonicalizationMethod() {
        return canonicalizationMethod.getAlgorithm();
    }

    public String getRedactableSignatureMethod() {
        return redactableSignatureAlgorithm.getAlgorithm();
    }

}

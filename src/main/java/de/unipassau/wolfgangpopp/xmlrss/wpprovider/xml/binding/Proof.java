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

/**
 * The Proof class is responsible for marshalling and unmarshalling the <code>Proof</code> element of the redactable
 * signature XML encoding. The proof element has to be specifically adjusted for every implementation. Implementations
 * have to implement their own encoding of the proof element.
 *
 * The XSD Schema of the proof is defined as following
 * <pre>
 * {@code <element name="Proof" type="anyType"/> }
 * </pre>
 *
 * @author Wolfgang Popp
 */
public abstract class Proof extends BindingElement<Proof> {
    @Override
    public String getTagName() {
        return "Proof";
    }
}

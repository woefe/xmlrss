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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;

import java.util.List;

/**
 * @author Wolfgang Popp
 */
public class GLRSSSignatureOutput implements SignatureOutput {

    private final GSRSSSignatureOutput gsrssOutput;
    private final List<GLRSSSignedPart> parts;

    GLRSSSignatureOutput(GSRSSSignatureOutput gsrssOutput, List<GLRSSSignedPart> parts) {
        this.gsrssOutput = gsrssOutput;
        this.parts = parts;
    }

    public GSRSSSignatureOutput getGsrssOutput() {
        return gsrssOutput;
    }

    public List<GLRSSSignedPart> getParts() {
        return parts;
    }

    @Override
    public boolean contains(byte[] part) {
        // TODO
        return false;
    }

    @Override
    public boolean containsAll(byte[]... part) {
        // TODO
        return false;
    }

    @Override
    public int size() {
        // TODO
        return 0;
    }
}

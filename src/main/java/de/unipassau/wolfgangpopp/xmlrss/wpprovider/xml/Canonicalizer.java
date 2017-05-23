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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Node;

/**
 * @author Wolfgang Popp
 */
public class Canonicalizer {

    private static org.apache.xml.security.c14n.Canonicalizer canonicalizer;

    static {
        Init.init();
        try {
            canonicalizer = org.apache.xml.security.c14n.Canonicalizer.getInstance(
                    org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS
            );
        } catch (InvalidCanonicalizerException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] canonicalize(Node node) throws CanonicalizationException {
        return canonicalizer.canonicalizeSubtree(node);
    }

}

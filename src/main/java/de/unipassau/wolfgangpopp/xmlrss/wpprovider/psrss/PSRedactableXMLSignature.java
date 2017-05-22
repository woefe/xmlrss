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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.AbstractRedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Reference;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.SimpleProof;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
abstract class PSRedactableXMLSignature extends AbstractRedactableXMLSignature<PSSignatureValue, SimpleProof> {

    private PSSignatureOutput.Builder builder;

    PSRedactableXMLSignature(RedactableSignature signature) throws RedactableXMLSignatureException {
        super(signature, PSSignatureValue.class, SimpleProof.class);
    }

    @Override
    protected String getRedactableSignatureMethod() {
        return "http://sec.uni-passau.de/2017/xmlrss/psrss";
    }

    @Override
    protected String getCanonicalizationMethod() {
        return com.sun.org.apache.xml.internal.security.c14n.Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;
    }

    @Override
    protected PSSignatureValue marshallSignatureValue(SignatureOutput signatureOutput)
            throws RedactableXMLSignatureException {

        return new PSSignatureValue((PSSignatureOutput) signatureOutput);
    }

    @Override
    protected Collection<Reference<SimpleProof>> marshallReferences(SignatureOutput signatureOutput)
            throws RedactableXMLSignatureException {

        Set<Reference<SimpleProof>> references = new HashSet<>();
        PSSignatureOutput output = (PSSignatureOutput) signatureOutput;
        for (PSSignatureOutput.SignedPart signedPart : output) {
            SimpleProof proof = new SimpleProof(signedPart.getProof());
            Pointer pointer = getPointerForMessagePart(signedPart.getElement().getArray());
            Reference<SimpleProof> reference = new Reference<>(pointer, proof);
            references.add(reference);
        }
        return references;
    }

    @Override
    protected Identifier createIdentifier(byte[] messagePart, int index) throws RedactableXMLSignatureException {
        return new Identifier(messagePart);
    }

    @Override
    protected void prepareUnmarshallReference(int messageSize, int index, Pointer pointer, SimpleProof proof)
            throws RedactableXMLSignatureException {

        ensureBuilderExists();
        try {
            builder.add(getMessagePartForPointer(pointer), proof.getBytes());
        } catch (PSRSSException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    private void ensureBuilderExists() {
        if (builder == null) {
            builder = new PSSignatureOutput.Builder();
        }
    }

    @Override
    protected void prepareUnmarshallSignatureValue(int messageSize, PSSignatureValue signatureValue)
            throws RedactableXMLSignatureException {

        ensureBuilderExists();
        builder.setAccumulator(signatureValue.getAccumulator())
                .setProofOfTag(signatureValue.getProofOfTag())
                .setTag(signatureValue.getTag());
    }

    @Override
    protected SignatureOutput doUnmarshall() throws RedactableXMLSignatureException {
        PSSignatureOutput output = builder.build();
        builder = null;
        return output;
    }

    public static class XMLPSRSSwithPSA extends PSRedactableXMLSignature {
        public XMLPSRSSwithPSA() throws NoSuchAlgorithmException, RedactableXMLSignatureException {
            super(RedactableSignature.getInstance("PSRSSwithPSA"));
        }
    }
}

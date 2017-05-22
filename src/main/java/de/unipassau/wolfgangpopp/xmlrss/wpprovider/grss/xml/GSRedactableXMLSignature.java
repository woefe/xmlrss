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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRSSSignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.AbstractRedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Proof;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Reference;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.SignatureValue;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.SimpleProof;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public abstract class GSRedactableXMLSignature extends AbstractRedactableXMLSignature {

    private GSRSSSignatureOutput.Builder builder;

    protected GSRedactableXMLSignature(RedactableSignature gsrss) throws RedactableXMLSignatureException {
        super(gsrss);
    }

    @Override
    protected String getRedactableSignatureMethod() {
        return "http://sec.uni-passau.de/2017/xmlrss/gsrss";
    }

    @Override
    protected String getCanonicalizationMethod() {
        return com.sun.org.apache.xml.internal.security.c14n.Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;
    }

    @Override
    protected GSSignatureValue marshallSignatureValue(SignatureOutput signatureOutput)
            throws RedactableXMLSignatureException {

        GSRSSSignatureOutput output = (GSRSSSignatureOutput) signatureOutput;
        return new GSSignatureValue(output.getDSigValue(), output.getAccumulatorValue());
    }

    @Override
    protected Collection<Reference> marshallReferences(SignatureOutput signatureOutput)
            throws RedactableXMLSignatureException {

        Set<Reference> references = new HashSet<>();
        GSRSSSignatureOutput output = (GSRSSSignatureOutput) signatureOutput;

        Map<ByteArray, byte[]> parts = output.getParts();
        for (Map.Entry<ByteArray, byte[]> signedPart : parts.entrySet()) {
            SimpleProof proof = new SimpleProof(signedPart.getValue());
            Pointer pointer = getPointerForMessagePart(signedPart.getKey().getArray());
            references.add(new Reference(pointer, proof));
        }
        return references;
    }

    @Override
    protected Identifier createIdentifier(byte[] messagePart, int index) throws RedactableXMLSignatureException {
        return new Identifier(messagePart);
    }

    @Override
    protected void prepareUnmarshallReference(int messageSize, int index, Pointer pointer, Proof proof)
            throws RedactableXMLSignatureException {

        SimpleProof simpleProof = ((SimpleProof) proof);
        ensureBuilderExists();
        builder.addSignedPart(new ByteArray(getMessagePartForPointer(pointer)),
                simpleProof.getBytes(), pointer.isRedactable());
    }

    @Override
    protected void prepareUnmarshallSignatureValue(int messageSize, SignatureValue signatureValue)
            throws RedactableXMLSignatureException {

        ensureBuilderExists();
        GSSignatureValue gsSignatureValue = ((GSSignatureValue) signatureValue);
        builder.setAccumulatorValue(gsSignatureValue.getAccumulatorValue())
                .setDSigValue(gsSignatureValue.getDSigValue());
    }

    @Override
    protected SignatureOutput doUnmarshall() throws RedactableXMLSignatureException {
        GSRSSSignatureOutput output = builder.build();
        builder = null;
        return output;
    }


    private void ensureBuilderExists() {
        if (builder == null) {
            builder = new GSRSSSignatureOutput.Builder();
        }
    }

    public static class GSRSSwithBPAccumulatorAndRSA extends GSRedactableXMLSignature {
        public GSRSSwithBPAccumulatorAndRSA() throws NoSuchAlgorithmException, RedactableXMLSignatureException {
            super(RedactableSignature.getInstance("GSRSSwithRSAandBPA"));
        }
    }
}

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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.AbstractRedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Proof;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Reference;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.SignatureValue;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Wolfgang Popp
 */
public abstract class GLRedactableXMLSignature extends AbstractRedactableXMLSignature {

    private GLRSSSignatureOutput.Builder builder;

    protected GLRedactableXMLSignature(RedactableSignature rss) {
        super(rss);
    }

    @Override
    protected String getRedactableSignatureMethod() {
        return "http://sec.uni-passau.de/2017/xmlrss/glrss";
    }

    @Override
    protected String getCanonicalizationMethod() {
        return com.sun.org.apache.xml.internal.security.c14n.Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;
    }

    @Override
    protected GSSignatureValue marshallSignatureValue(SignatureOutput signatureOutput) {
        GLRSSSignatureOutput output = (GLRSSSignatureOutput) signatureOutput;
        return new GSSignatureValue(output.getGsDsigValue(), output.getGsAccumulator());
    }

    @Override
    protected Collection<Reference> marshallReferences(SignatureOutput signatureOutput) {
        GLRSSSignatureOutput output = (GLRSSSignatureOutput) signatureOutput;
        List<Reference> references = new LinkedList<>();

        for (GLRSSSignatureOutput.GLRSSSignedPart glrssSignedPart : output.getParts()) {
            GLProof proof = new GLProof(glrssSignedPart);
            Pointer pointer = getPointerForMessagePart(glrssSignedPart.getMessagePart());
            references.add(new Reference(pointer, proof));
        }

        return references;
    }

    @Override
    protected Identifier createIdentifier(byte[] messagePart, int index) {
        return new Identifier(messagePart, index);
    }

    @Override
    protected void prepareUnmarshallReference(int messageSize, int index, Pointer pointer, Proof proof)
            throws RedactableXMLSignatureException {

        GLProof glProof = (GLProof) proof;
        ensureBuilderExists(messageSize);
        builder.setMessagePart(index, getMessagePartForPointer(pointer))
                .setRedactable(index, pointer.isRedactable())
                .setRandomValue(index, glProof.getRandomValue())
                .setAccValue(index, glProof.getAccumulatorValue())
                .setWitnesses(index, glProof.getWitnesses())
                .setGSProof(index, glProof.getGsProof());
    }

    @Override
    protected void prepareUnmarshallSignatureValue(int messageSize, SignatureValue signatureValue) {
        ensureBuilderExists(messageSize);

        GSSignatureValue gsSignatureValue = (GSSignatureValue) signatureValue;

        builder.setGSAccumulator(gsSignatureValue.getAccumulatorValue())
                .setGSDsigValue(gsSignatureValue.getDSigValue());

    }

    private void ensureBuilderExists(int size) {
        if (builder == null) {
            builder = new GLRSSSignatureOutput.Builder(size);
        }
    }

    @Override
    protected SignatureOutput doUnmarshall() {
        GLRSSSignatureOutput signatureOutput = builder.build();
        builder = null;
        return signatureOutput;
    }


    public static class GLRSSwithBPAccumulatorAndRSA extends GLRedactableXMLSignature {
        public GLRSSwithBPAccumulatorAndRSA() throws RedactableXMLSignatureException, NoSuchAlgorithmException {
            super(RedactableSignature.getInstance("GLRSSwithRSAandBPA"));
        }
    }

}

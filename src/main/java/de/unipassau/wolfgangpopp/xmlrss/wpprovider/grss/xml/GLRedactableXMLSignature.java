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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Reference;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Wolfgang Popp
 */
public abstract class GLRedactableXMLSignature extends AbstractRedactableXMLSignature<GSSignatureValue, GLProof> {

    private GLRSSSignatureOutput.Builder builder;

    protected GLRedactableXMLSignature(RedactableSignature rss) {
        super(rss, GSSignatureValue.class, GLProof.class);
    }

    @Override
    protected GSSignatureValue marshallSignatureValue(SignatureOutput signatureOutput) {
        GLRSSSignatureOutput output = (GLRSSSignatureOutput) signatureOutput;
        return new GSSignatureValue(output.getGsDsigValue(), output.getGsAccumulator());
    }

    @Override
    protected Collection<Reference<GLProof>> marshallReferences(SignatureOutput signatureOutput) {
        GLRSSSignatureOutput output = (GLRSSSignatureOutput) signatureOutput;
        List<Reference<GLProof>> references = new LinkedList<>();

        for (GLRSSSignatureOutput.GLRSSSignedPart glrssSignedPart : output.getParts()) {
            GLProof proof = new GLProof(glrssSignedPart);
            Pointer pointer = getPointerForMessagePart(glrssSignedPart.getMessagePart());
            references.add(new Reference<>(pointer, proof));
        }

        return references;
    }

    @Override
    protected Identifier createIdentifier(byte[] messagePart, int index) {
        return new Identifier(messagePart, index);
    }

    @Override
    protected void prepareUnmarshallReference(int messageSize, int index, Pointer pointer, GLProof proof) throws RedactableXMLSignatureException {
        ensureBuilderExists(messageSize);
        builder.setMessagePart(index, getMessagePartForPointer(pointer))
                .setRedactable(index, pointer.isRedactable())
                .setRandomValue(index, proof.getRandomValue())
                .setAccValue(index, proof.getAccumulatorValue())
                .setWitnesses(index, proof.getWitnesses())
                .setGSProof(index, proof.getGsProof());
    }

    @Override
    protected void prepareUnmarshallSignatureValue(int messageSize, GSSignatureValue signatureValue) {
        ensureBuilderExists(messageSize);
        builder.setGSAccumulator(signatureValue.getAccumulatorValue())
                .setGSDsigValue(signatureValue.getDSigValue());

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

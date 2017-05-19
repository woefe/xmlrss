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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Reference;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.SimpleProof;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public class GSRedactableXMLSignature extends AbstractRedactableXMLSignature<GSSignatureValue, SimpleProof> {

    private GSRSSSignatureOutput.Builder builder;

    protected GSRedactableXMLSignature(RedactableSignature gsrss) throws RedactableXMLSignatureException {
        super(gsrss, GSSignatureValue.class, SimpleProof.class);
    }

    @Override
    protected GSSignatureValue marshallSignatureValue(SignatureOutput signatureOutput)
            throws RedactableXMLSignatureException {

        GSRSSSignatureOutput output = (GSRSSSignatureOutput) signatureOutput;
        return new GSSignatureValue(output.getDSigValue(), output.getAccumulatorValue());
    }

    @Override
    protected Collection<Reference<SimpleProof>> marshallReferences(SignatureOutput signatureOutput)
            throws RedactableXMLSignatureException {

        Set<Reference<SimpleProof>> references = new HashSet<>();
        GSRSSSignatureOutput output = (GSRSSSignatureOutput) signatureOutput;

        Map<ByteArray, byte[]> parts = output.getParts();
        for (Map.Entry<ByteArray, byte[]> signedPart : parts.entrySet()) {
            SimpleProof proof = new SimpleProof(signedPart.getValue());
            Pointer pointer = getPointerForMessagePart(signedPart.getKey().getArray());
            references.add(new Reference<>(pointer, proof));
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
        builder.addSignedPart(new ByteArray(getMessagePartForPointer(pointer)),
                proof.getBytes(), pointer.isRedactable());
    }

    @Override
    protected void prepareUnmarshallSignatureValue(int messageSize, GSSignatureValue signatureValue)
            throws RedactableXMLSignatureException {

        ensureBuilderExists();
        builder.setAccumulatorValue(signatureValue.getAccumulatorValue())
                .setDSigValue(signatureValue.getDSigValue());
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

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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Accumulator;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The {@link GSRedactableSignature} class implements the general RSS for sets as descibed in
 * http://henrich.poehls.com/papers/2015_DerlerPoehlsSamelinSlamanig-GeneralFrameworkForRedactableSignatures_ICISC.pdf
 *
 * @author Wolfgang Popp
 */
public abstract class GSRedactableSignature extends RedactableSignatureSpi {

    private final Accumulator accumulator;
    private final Signature dsig;
    private final Map<ByteArray, Boolean> messageParts = new HashMap<>();
    private SecureRandom random;
    private PublicKey accPublicKey;
    private PrivateKey accPrivateKey;
    private PublicKey dsigPublicKey;
    private PrivateKey dsigPrivateKey;
    private KeyPair dsigkeyPair;
    private KeyPair acckeyPair;

    protected GSRedactableSignature(Accumulator accumulator, Signature dsig) {
        this.accumulator = accumulator;
        this.dsig = dsig;
    }

    @Override
    protected void engineInitSign(KeyPair keyPair) throws InvalidKeyException {
        engineInitSign(keyPair, new SecureRandom());
    }

    @Override
    protected void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        reset();
        checkAndSetKeyPair(keyPair);
        this.random = random;
        dsig.initSign(dsigPrivateKey, random);
        accumulator.initWitness(acckeyPair, random);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        reset();
        checkAndSetPublicKey(publicKey);
        dsig.initVerify(dsigPublicKey);
        accumulator.initVerify(accPublicKey);
    }

    @Override
    protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        reset();
        checkAndSetPublicKey(publicKey);
    }

    @Override
    protected Identifier engineAddPart(byte[] part, boolean isRedactable) throws RedactableSignatureException {
        if (messageParts.put(new ByteArray(part), isRedactable) != null) {
            throw new RedactableSignatureException(
                    "This algorithm is set based and therefore does not support duplicates");
        }
        return new Identifier(part);
    }

    @Override
    protected void engineAddIdentifier(Identifier identifier) throws RedactableSignatureException {
        engineAddPart(identifier.getBytes(), true);
    }

    @Override
    protected SignatureOutput engineSign() throws RedactableSignatureException {
        byte[][] elements = new byte[messageParts.size()][];
        GSRSSSignatureOutput.Builder builder = new GSRSSSignatureOutput.Builder();

        int index = 0;
        for (ByteArray redactablePart : messageParts.keySet()) {
            elements[index++] = redactablePart.getArray();
        }

        try {
            accumulator.digest(elements);
            builder.setAccumulatorValue(accumulator.getAccumulatorValue());
        } catch (AccumulatorException e) {
            throw new RedactableSignatureException(e);
        }

        Set<ByteArray> nonRedactableParts = new HashSet<>();
        for (Map.Entry<ByteArray, Boolean> entry : messageParts.entrySet()) {
            if (!entry.getValue()) {
                nonRedactableParts.add(entry.getKey());
            }
        }

        for (ByteArray element : sortNonRedactableParts(nonRedactableParts)) {
            try {
                dsig.update(element.getArray());
            } catch (SignatureException e) {
                throw new RedactableSignatureException(e);
            }
        }

        try {
            builder.setDSigValue(dsig.sign());
        } catch (SignatureException e) {
            throw new RedactableSignatureException(e);
        }

        for (Map.Entry<ByteArray, Boolean> entry : messageParts.entrySet()) {
            ByteArray part = entry.getKey();
            try {
                builder.addSignedPart(part, accumulator.createWitness(part.getArray()), entry.getValue());
            } catch (AccumulatorException e) {
                throw new RedactableSignatureException(e);
            }
        }

        messageParts.clear();

        return builder.build();
    }

    @Override
    protected boolean engineVerify(SignatureOutput signature) throws RedactableSignatureException {
        if (!(signature instanceof GSRSSSignatureOutput)) {
            throw new RedactableSignatureException("wrong signature type");
        }

        GSRSSSignatureOutput signatureOutput = ((GSRSSSignatureOutput) signature);

        try {
            accumulator.restoreVerify(signatureOutput.getAccumulatorValue());
        } catch (AccumulatorException e) {
            throw new RedactableSignatureException(e);
        }

        List<ByteArray> ordered = sortNonRedactableParts(signatureOutput.getNonRedactableParts());
        for (ByteArray element : ordered) {
            try {
                dsig.update(element.getArray());
            } catch (SignatureException e) {
                throw new RedactableSignatureException(e);
            }
        }

        boolean valid;
        try {
            valid = dsig.verify(signatureOutput.getDSigValue());
        } catch (SignatureException e) {
            throw new RedactableSignatureException(e);
        }

        Map<ByteArray, byte[]> redactableParts = signatureOutput.getParts();
        for (ByteArray key : redactableParts.keySet()) {
            try {
                valid = valid && accumulator.verify(redactableParts.get(key), key.getArray());
            } catch (AccumulatorException e) {
                throw new RedactableSignatureException(e);
            }
        }

        return valid;
    }

    @Override
    protected SignatureOutput engineRedact(SignatureOutput signature) throws RedactableSignatureException {
        if (!(signature instanceof GSRSSSignatureOutput)) {
            throw new RedactableSignatureException("wrong signature type");
        }
        GSRSSSignatureOutput signatureOutput = (GSRSSSignatureOutput) signature;
        GSRSSSignatureOutput.Builder builder = new GSRSSSignatureOutput.Builder();
        Map<ByteArray, byte[]> signedParts = signatureOutput.getParts();
        Set<ByteArray> parts = signedParts.keySet();
        Set<ByteArray> nonRedactableParts = signatureOutput.getNonRedactableParts();

        builder.setDSigValue(signatureOutput.getDSigValue())
                .setAccumulatorValue(signatureOutput.getAccumulatorValue());

        for (ByteArray messagePart : messageParts.keySet()) {
            if (nonRedactableParts.contains(messagePart)) {
                throw new RedactableSignatureException("Cannot perform the redaction since a given part is not redactable");
            }
        }

        for (ByteArray part : parts) {
            if (!messageParts.keySet().contains(part)) {
                builder.addSignedPart(part, signedParts.get(part), signatureOutput.isRedactable(new Identifier(part)));
            }
        }

        messageParts.clear();

        return builder.build();
    }

    @Override
    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {

    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private void reset() {
        this.random = null;
        this.accPublicKey = null;
        this.accPrivateKey = null;
        this.dsigPublicKey = null;
        this.dsigPrivateKey = null;
        this.dsigkeyPair = null;
        this.acckeyPair = null;
        this.messageParts.clear();
    }

    private void checkAndSetKeyPair(KeyPair keyPair) throws InvalidKeyException {
        checkAndSetPublicKey(keyPair.getPublic());

        if (!(keyPair.getPrivate() instanceof GSRSSPrivateKey)) {
            throw new InvalidKeyException("The given private key cannot be used with this algorithm");
        }
        dsigPrivateKey = ((GSRSSPrivateKey) keyPair.getPrivate()).getDSigKey();
        accPrivateKey = ((GSRSSPrivateKey) keyPair.getPrivate()).getAccumulatorKey();
        acckeyPair = new KeyPair(accPublicKey, accPrivateKey);
        dsigkeyPair = new KeyPair(dsigPublicKey, dsigPrivateKey);
    }

    private void checkAndSetPublicKey(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof GSRSSPublicKey)) {
            throw new InvalidKeyException("The given public key cannot be used with this algorithm");
        }
        accPublicKey = ((GSRSSPublicKey) publicKey).getAccumulatorKey();
        dsigPublicKey = ((GSRSSPublicKey) publicKey).getDSigKey();
    }

    private List<ByteArray> sortNonRedactableParts(Collection<ByteArray> nonRedactable) {
        List<ByteArray> ordered = new ArrayList<>(nonRedactable.size());
        ordered.addAll(nonRedactable);
        ordered.sort(new Comparator<ByteArray>() {
            @Override
            public int compare(ByteArray o1, ByteArray o2) {
                return o1.compareTo(o2);
            }
        });

        return ordered;
    }

    public static class GSRSSwithBPAccumulatorAndRSA extends GSRedactableSignature {
        public GSRSSwithBPAccumulatorAndRSA() throws NoSuchAlgorithmException {
            super(Accumulator.getInstance("BPA"), Signature.getInstance("SHA256withRSA"));
        }
    }
}

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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArrayWrapper;

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
    private SecureRandom random;
    private PublicKey accPublicKey;
    private PrivateKey accPrivateKey;
    private PublicKey dsigPublicKey;
    private PrivateKey dsigPrivateKey;
    private KeyPair dsigkeyPair;
    private KeyPair acckeyPair;
    private Set<ByteArrayWrapper> redactableParts = new HashSet<>();
    private Set<ByteArrayWrapper> nonRedactableParts = new HashSet<>();

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
        checkAndSetKeyPair(keyPair);
        this.random = random;
        dsig.initSign(dsigPrivateKey, random);
        accumulator.initWitness(acckeyPair, random);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        checkAndSetPublicKey(publicKey);
        dsig.initVerify(publicKey);
        accumulator.initVerify(publicKey);
    }

    @Override
    protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        checkAndSetPublicKey(publicKey);
    }

    @Override
    protected void engineAddPart(byte[] part, boolean redactable) throws RedactableSignatureException {
        Set<ByteArrayWrapper> set;
        if (redactable) {
            set = this.redactableParts;
        } else {
            set = this.nonRedactableParts;
        }

        if (!set.add(new ByteArrayWrapper(part))) {
            throw new RedactableSignatureException(
                    "This algorithm is set based and therefore does not support duplicates");
        }
    }

    @Override
    protected SignatureOutput engineSign() throws RedactableSignatureException {
        byte[][] elements = new byte[redactableParts.size()][];
        GRSSSignatureOutput.Builder builder = new GRSSSignatureOutput.Builder();

        int index = 0;
        for (ByteArrayWrapper redactablePart : redactableParts) {
            elements[index++] = redactablePart.getArray();
        }

        try {
            accumulator.digest(elements);
            builder.setAccumulatorValue(accumulator.getAccumulatorValue());
        } catch (AccumulatorException e) {
            throw new RedactableSignatureException(e);
        }

        for (ByteArrayWrapper element : orderNonRedactableParts(nonRedactableParts)) {
            try {
                dsig.update(element.getArray());
                builder.addNonRedactablePart(element);
            } catch (SignatureException e) {
                throw new RedactableSignatureException(e);
            }
        }

        try {
            builder.setDSigValue(dsig.sign());
        } catch (SignatureException e) {
            throw new RedactableSignatureException(e);
        }

        for (ByteArrayWrapper part : redactableParts) {
            try {
                builder.addRedactablePart(part, accumulator.createWitness(part.getArray()));
            } catch (AccumulatorException e) {
                throw new RedactableSignatureException(e);
            }
        }

        return builder.build();
    }

    @Override
    protected boolean engineVerify(SignatureOutput signature) throws RedactableSignatureException {
        if (!(signature instanceof GRSSSignatureOutput)) {
            throw new RedactableSignatureException("wrong signature type");
        }

        GRSSSignatureOutput signatureOutput = ((GRSSSignatureOutput) signature);

        try {
            accumulator.restoreVerify(signatureOutput.getAccumulatorValue());
        } catch (AccumulatorException e) {
            throw new RedactableSignatureException(e);
        }

        List<ByteArrayWrapper> ordered = orderNonRedactableParts(signatureOutput.getNonRedactableParts());
        for (ByteArrayWrapper element : ordered) {
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

        Map<ByteArrayWrapper, byte[]> redactableParts = signatureOutput.getRedactableParts();
        for (ByteArrayWrapper key : redactableParts.keySet()) {
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
        if (!(signature instanceof GRSSSignatureOutput)) {
            throw new RedactableSignatureException("wrong signature type");
        }
        GRSSSignatureOutput signatureOutput = (GRSSSignatureOutput) signature;
        GRSSSignatureOutput.Builder builder = new GRSSSignatureOutput.Builder();
        Map<ByteArrayWrapper, byte[]> signedParts = signatureOutput.getRedactableParts();
        Set<ByteArrayWrapper> parts = signedParts.keySet();

        builder.setDSigValue(signatureOutput.getDSigValue())
                .setAccumulatorValue(signatureOutput.getAccumulatorValue())
                .addNonRedactableParts(signatureOutput.getNonRedactableParts());

        for (ByteArrayWrapper part : this.redactableParts) {
            if (!parts.contains(part)) {
                builder.addRedactablePart(part, signedParts.get(part));
            }
        }

        return builder.build();
    }

    @Override
    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {

    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private void checkAndSetKeyPair(KeyPair keyPair) throws InvalidKeyException {
        checkAndSetPublicKey(keyPair.getPublic());

        if (!(keyPair.getPrivate() instanceof GRSSPrivateKey)) {
            throw new InvalidKeyException("The given private key cannot be used with this algorithm");
        }
        dsigPrivateKey = ((GRSSPrivateKey) keyPair.getPrivate()).getDSigKey();
        accPrivateKey = ((GRSSPrivateKey) keyPair.getPrivate()).getAccumulatorKey();
        acckeyPair = new KeyPair(accPublicKey, accPrivateKey);
        dsigkeyPair = new KeyPair(dsigPublicKey, dsigPrivateKey);
    }

    private void checkAndSetPublicKey(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof GRSSPublicKey)) {
            throw new InvalidKeyException("The given public key cannot be used with this algorithm");
        }
        accPublicKey = ((GRSSPublicKey) publicKey).getAccumulatorKey();
        dsigPublicKey = ((GRSSPublicKey) publicKey).getDSigKey();
    }

    private List<ByteArrayWrapper> orderNonRedactableParts(Collection<ByteArrayWrapper> nonRedactable) {
        List<ByteArrayWrapper> ordered = new ArrayList<>(nonRedactable.size());
        ordered.addAll(nonRedactable);
        ordered.sort(new Comparator<ByteArrayWrapper>() {
            @Override
            public int compare(ByteArrayWrapper o1, ByteArrayWrapper o2) {
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

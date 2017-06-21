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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The <code>GLRedactableSignature</code> implements the general redactable signature for lists as described in
 * http://henrich.poehls.com/papers/2015_DerlerPoehlsSamelinSlamanig-GeneralFrameworkForRedactableSignatures_ICISC.pdf
 *
 * @author Wolfgang Popp
 */
public abstract class GLRedactableSignature extends RedactableSignatureSpi {

    private final Accumulator posAccumulator;
    private final RedactableSignature gsrss;
    private final List<ByteArray> parts = new ArrayList<>();
    private final List<Boolean> isRedactable = new ArrayList<>();
    private final Set<Identifier> identifiers = new HashSet<>();
    private PrivateKey gsrssPrivateKey;
    private PrivateKey accPrivateKey;
    private PublicKey gsrssPublicKey;
    private PublicKey accPublicKey;
    private KeyPair gsrssKeyPair;
    private KeyPair accKeyPair;
    private SecureRandom random;
    private int accByteLength;

    protected GLRedactableSignature(Accumulator posAccumulator, RedactableSignature gsrss) {
        this.posAccumulator = posAccumulator;
        this.gsrss = gsrss;
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
        gsrss.initSign(gsrssKeyPair);
        posAccumulator.initWitness(accKeyPair);
        try {
            posAccumulator.digest("asdf".getBytes(), "asdff".getBytes());
            accByteLength = posAccumulator.getAccumulatorValue().length;
        } catch (AccumulatorException e) {
            throw new IllegalStateException("Cannot determine accumulator bitlength");
        }
        posAccumulator.initWitness(accKeyPair);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        reset();
        checkAndSetPublicKey(publicKey);
        posAccumulator.initVerify(accPublicKey);
        gsrss.initVerify(gsrssPublicKey);
    }

    @Override
    protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        reset();
        checkAndSetPublicKey(publicKey);
        gsrss.initRedact(gsrssPublicKey);
    }

    @Override
    protected Identifier engineAddPart(byte[] part, boolean isRedactable) throws RedactableSignatureException {
        this.parts.add(new ByteArray(part));
        this.isRedactable.add(isRedactable);
        return new Identifier(part, parts.size() - 1);
    }

    @Override
    protected void engineAddIdentifier(Identifier identifier) throws RedactableSignatureException {
        if (!identifiers.add(identifier)) {
            throw new RedactableSignatureException("identifiers cannot be added twice");
        }
    }

    @Override
    protected SignatureOutput engineSign() throws RedactableSignatureException {

        GLRSSSignatureOutput.Builder builder = new GLRSSSignatureOutput.Builder(parts.size());
        byte[][] randomValues = new byte[parts.size()][accByteLength];

        for (int i = 0; i < parts.size(); i++) {
            random.nextBytes(randomValues[i]);
        }

        for (int i = 0; i < parts.size(); i++) {
            byte[] accumulatorValue;
            byte[] messagePart = parts.get(i).getArray();
            boolean isRedactable = this.isRedactable.get(i);

            try {
                byte[][] randomRange = Arrays.copyOfRange(randomValues, 0, i + 1);
                posAccumulator.digest(randomRange);
                accumulatorValue = posAccumulator.getAccumulatorValue();

                for (byte[] bytes : randomRange) {
                    builder.addWittness(i, posAccumulator.createWitness(bytes));
                }
            } catch (AccumulatorException e) {
                throw new RedactableSignatureException(e);
            }

            byte[] concat = GLRSSSignatureOutput.concat(messagePart, accumulatorValue, randomValues[i]);

            builder.setMessagePart(i, messagePart)
                    .setRedactable(i, isRedactable)
                    .setRandomValue(i, randomValues[i])
                    .setAccValue(i, accumulatorValue);

            gsrss.addPart(concat, isRedactable);
        }

        builder.embedGSOutput((GSRSSSignatureOutput) gsrss.sign());

        parts.clear();
        isRedactable.clear();

        return builder.build();
    }

    @Override
    protected boolean engineVerify(SignatureOutput signature) throws RedactableSignatureException {
        if (!(signature instanceof GLRSSSignatureOutput)) {
            throw new RedactableSignatureException("wrong signature type");
        }

        GLRSSSignatureOutput glrssSignatureOutput = (GLRSSSignatureOutput) signature;
        List<GLRSSSignatureOutput.GLRSSSignedPart> parts = glrssSignatureOutput.getParts();
        boolean verify = gsrss.verify(glrssSignatureOutput.extractGSOutput());

        for (int i = 0; i < parts.size() && verify; i++) {
            GLRSSSignatureOutput.GLRSSSignedPart part = parts.get(i);

            try {
                posAccumulator.restoreVerify(part.getAccumulatorValue());
                for (int j = 0; j < i && verify; j++) {
                    byte[] witness = part.getWitnesses().get(j).getArray();
                    byte[] randomValue = parts.get(j).getRandomValue();
                    verify = posAccumulator.verify(witness, randomValue);
                }
            } catch (AccumulatorException e) {
                throw new RedactableSignatureException(e);
            }
        }

        //TODO Check if all Non redactable parts are present

        return verify;
    }

    @Override
    protected SignatureOutput engineRedact(SignatureOutput signature) throws RedactableSignatureException {
        if (!(signature instanceof GLRSSSignatureOutput)) {
            throw new RedactableSignatureException("wrong signature type");
        }

        GLRSSSignatureOutput original = (GLRSSSignatureOutput) signature;
        List<GLRSSSignatureOutput.GLRSSSignedPart> parts = ((GLRSSSignatureOutput) signature).getParts();
        int size = parts.size() - identifiers.size();
        GLRSSSignatureOutput.Builder builder = new GLRSSSignatureOutput.Builder(size);

        int builderIndex = 0;
        for (int i = 0; i < parts.size(); i++) {
            GLRSSSignatureOutput.GLRSSSignedPart part = parts.get(i);
            if (!isIdentified(i, part)) {
                ArrayList<ByteArray> copy = new ArrayList<>(part.getWitnesses());
                removeWitnesses(copy);

                builder.setMessagePart(builderIndex, part.getMessagePart())
                        .setRedactable(builderIndex, part.isRedactable())
                        .setRandomValue(builderIndex, part.getRandomValue())
                        .setAccValue(builderIndex, part.getAccumulatorValue())
                        .setWitnesses(builderIndex, copy);

                ++builderIndex;
            }
        }

        // redact gsrss signature output
        for (Identifier identifier : identifiers) {
            GLRSSSignatureOutput.GLRSSSignedPart part = parts.get(identifier.getPosition());
            ByteArray concat = new ByteArray(part.getMessagePart()).concat(part.getAccumulatorValue())
                    .concat(part.getRandomValue());
            gsrss.addIdentifier(new Identifier(concat));
        }

        builder.embedGSOutput((GSRSSSignatureOutput) gsrss.redact(original.extractGSOutput()));

        identifiers.clear();

        return builder.build();
    }

    private void removeWitnesses(List<ByteArray> witnesses) {
        ByteArray invalid = new ByteArray(null);
        for (Identifier identifier : identifiers) {
            int position = identifier.getPosition();
            if (position < witnesses.size()) {
                witnesses.set(position, invalid);
            }
        }
        witnesses.removeAll(Collections.singleton(invalid));
    }

    private boolean isIdentified(int index, GLRSSSignatureOutput.GLRSSSignedPart part) {
        return identifiers.contains(new Identifier(part.getMessagePart(), index));
    }

    @Override
    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {

    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private void reset() {
        parts.clear();
        isRedactable.clear();
        identifiers.clear();
        gsrssPrivateKey = null;
        accPrivateKey = null;
        gsrssPublicKey = null;
        accPublicKey = null;
        gsrssKeyPair = null;
        accKeyPair = null;
        random = null;
        accByteLength = -1;
    }

    private void checkAndSetKeyPair(KeyPair keyPair) throws InvalidKeyException {
        checkAndSetPublicKey(keyPair.getPublic());
        PrivateKey privateKey = keyPair.getPrivate();

        if (!(privateKey instanceof GLRSSPrivateKey)) {
            throw new InvalidKeyException("The given public key cannot be used with this algorithm");
        }

        gsrssPrivateKey = ((GLRSSPrivateKey) privateKey).getGsrssKey();
        accPrivateKey = ((GLRSSPrivateKey) privateKey).getAccumulatorKey();
        gsrssKeyPair = new KeyPair(gsrssPublicKey, gsrssPrivateKey);
        accKeyPair = new KeyPair(accPublicKey, accPrivateKey);
    }

    private void checkAndSetPublicKey(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof GLRSSPublicKey)) {
            throw new InvalidKeyException("The given public key cannot be used with this algorithm");
        }
        gsrssPublicKey = ((GLRSSPublicKey) publicKey).getGsrssKey();
        accPublicKey = ((GLRSSPublicKey) publicKey).getAccumulatorKey();
    }


    public static class GLRSSwithBPAccumulatorAndRSA extends GLRedactableSignature {
        public GLRSSwithBPAccumulatorAndRSA() throws NoSuchAlgorithmException {
            //TODO set ord(ADM)
            super(Accumulator.getInstance("BPA"), RedactableSignature.getInstance("GSRSSwithRSAandBPA"));
        }
    }
}

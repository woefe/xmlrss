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
import java.util.List;

/**
 * @author Wolfgang Popp
 */
public abstract class GLRedactableSignature extends RedactableSignatureSpi {

    private final Accumulator posAccumulator;
    private final RedactableSignature gsrss;
    private final List<GLRSSSignedPart> parts = new ArrayList<>();
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
    }

    @Override
    protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        reset();
        checkAndSetPublicKey(publicKey);
    }

    @Override
    protected void engineAddPart(byte[] part, boolean isRedactable) throws RedactableSignatureException {
        GLRSSSignedPart glrssPart = new GLRSSSignedPart();
        glrssPart.setMessagePart(part);
        glrssPart.setRedactable(isRedactable);
        parts.add(glrssPart);
    }

    @Override
    protected SignatureOutput engineSign() throws RedactableSignatureException {

        for (GLRSSSignedPart part : parts) {
            byte[] randomValue = new byte[accByteLength];
            random.nextBytes(randomValue);
            part.setRandomValue(randomValue);
        }

        for (int i = 0; i < parts.size(); i++) {
            GLRSSSignedPart part = parts.get(i);
            List<ByteArray> witnesses = part.getWitnesses();
            byte[][] randomValues = new byte[i + 1][];

            for (int j = 0; j < i; j++) {
                randomValues[j] = parts.get(j).getRandomValue();
            }

            try {
                posAccumulator.digest(randomValues);
                part.setAccumulatorValue(posAccumulator.getAccumulatorValue());
            } catch (AccumulatorException e) {
                throw new RedactableSignatureException(e);
            }

            for (byte[] bytes : randomValues) {
                try {
                    witnesses.add(new ByteArray(posAccumulator.createWitness(bytes)));
                } catch (AccumulatorException e) {
                    throw new RedactableSignatureException(e);
                }
            }

            ByteArray concat = new ByteArray(part.getMessagePart()).concat(part.getAccumulatorValue())
                    .concat(part.getRandomValue());

            gsrss.addPart(concat.getArray(), part.isRedactable());
        }

        return new GLRSSSignatureOutput((GSRSSSignatureOutput) gsrss.sign(), parts);
    }

    @Override
    protected boolean engineVerify(SignatureOutput signature) throws RedactableSignatureException {
        return false;
    }

    @Override
    protected SignatureOutput engineRedact(SignatureOutput signature) throws RedactableSignatureException {
        return null;
    }

    @Override
    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {

    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private void reset() {
        /*
        private PrivateKey gsrssPrivateKey;
        private PrivateKey accPrivateKey;
        private PublicKey gsrssPublicKey;
        private PublicKey accPublicKey;
        private KeyPair gsrssKeyPair;
        private KeyPair accKeyPair;
        private SecureRandom random;
        private int accByteLength;
        */
        parts.clear();
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
        gsrssPublicKey = ((GSRSSPublicKey) publicKey).getAccumulatorKey();
        accPublicKey = ((GSRSSPublicKey) publicKey).getDSigKey();
    }


    public static class GLRSSwithBPAccumulatorAndRSA extends GLRedactableSignature {
        public GLRSSwithBPAccumulatorAndRSA() throws NoSuchAlgorithmException {
            super(Accumulator.getInstance("BPA"), RedactableSignature.getInstance("GSRSSwithRSAandBPA"));
        }
    }
}

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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public class GLRSSSignatureOutput implements SignatureOutput {

    private final List<GLRSSSignedPart> parts;
    private final Set<ByteArray> messageParts;
    private final byte[] gsAccumulator;
    private final byte[] gsDsigValue;


    GLRSSSignatureOutput(List<GLRSSSignedPart> parts, byte[] gsAccumulator, byte[] gsDsigValue) {
        this.parts = parts;
        Set<ByteArray> messageParts = new HashSet<>(size());
        for (GLRSSSignedPart part : parts) {
            messageParts.add(new ByteArray(part.getMessagePart()));
        }
        this.messageParts = Collections.unmodifiableSet(messageParts);
        this.gsAccumulator = gsAccumulator;
        this.gsDsigValue = gsDsigValue;
    }

    public List<GLRSSSignedPart> getParts() {
        return Collections.unmodifiableList(parts);
    }

    public byte[] getGsAccumulator() {
        return Arrays.copyOf(gsAccumulator, gsAccumulator.length);
    }

    public byte[] getGsDsigValue() {
        return Arrays.copyOf(gsDsigValue, gsDsigValue.length);
    }

    public GSRSSSignatureOutput extractGSOutput() {
        GSRSSSignatureOutput.Builder builder = new GSRSSSignatureOutput.Builder();
        builder.setDSigValue(getGsDsigValue())
                .setAccumulatorValue(getGsAccumulator());

        for (GLRSSSignatureOutput.GLRSSSignedPart glrssSignedPart : getParts()) {
            byte[] value = glrssSignedPart.toGSIdentifier().getBytes();
            builder.addSignedPart(value, glrssSignedPart.getGsProof(), glrssSignedPart.isRedactable());
        }

        return builder.build();
    }

    static byte[] concat(byte[] messagePart, byte[] accumulatorValue, byte[] randomValue) {
        return new ByteArray(messagePart).concat(accumulatorValue).concat(randomValue).getArray();
    }


    @Override
    public boolean contains(byte[] part) {
        return messageParts.contains(new ByteArray(part));
    }

    @Override
    public boolean contains(Identifier identifier) {
        int position = identifier.getPosition();
        return !(position < 0 || position >= size()) &&
                Arrays.equals(parts.get(position).getMessagePart(), identifier.getBytes());
    }

    @Override
    public boolean containsAll(byte[]... parts) {
        boolean areAllContained = true;
        for (byte[] part : parts) {
            areAllContained = areAllContained && contains(part);
        }
        return areAllContained;
    }

    @Override
    public boolean isRedactable(Identifier identifier) {
        //TODO
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public byte[] getMessagePart(Identifier identifier) {
        if (!contains(identifier)) {
            return null;
        }
        return parts.get(identifier.getPosition()).getMessagePart();
    }

    @Override
    public byte[] getProof(Identifier identifier) {
        //TODO
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public int size() {
        return parts.size();
    }

    public static class Builder {

        private final GLRSSSignedPart[] parts;
        private byte[] gsDsigValue;
        private byte[] gsAccumulator;

        public Builder(int size) {
            parts = new GLRSSSignedPart[size];
            for (int i = 0; i < size; i++) {
                parts[i] = new GLRSSSignedPart();
            }
        }

        public Builder setMessagePart(int index, byte[] messagePart) {
            parts[index].messagePart = Arrays.copyOf(messagePart, messagePart.length);
            return this;
        }

        public Builder setRedactable(int index, boolean isRedactable) {
            parts[index].isRedactable = isRedactable;
            return this;
        }

        public Builder setRandomValue(int index, byte[] randomValue) {
            parts[index].randomValue = Arrays.copyOf(randomValue, randomValue.length);
            return this;
        }

        public Builder setGSProof(int index, byte[] proof) {
            parts[index].gsProof = proof;
            return this;
        }

        public Builder addWittness(int index, byte[] wittness) {
            parts[index].witnesses.add(new ByteArray(Arrays.copyOf(wittness, wittness.length)));
            return this;
        }

        public Builder setWitnesses(int index, List<ByteArray> witnesses) {
            for (ByteArray witness : witnesses) {
                addWittness(index, witness.getArray());
            }
            return this;
        }

        public Builder setAccValue(int index, byte[] accumulatorValue) {
            parts[index].accumulatorValue = Arrays.copyOf(accumulatorValue, accumulatorValue.length);
            return this;
        }

        public Builder setGSAccumulator(byte[] accumulator) {
            this.gsAccumulator = Arrays.copyOf(accumulator, accumulator.length);
            return this;
        }

        public Builder setGSDsigValue(byte[] dsigValue) {
            this.gsDsigValue = Arrays.copyOf(dsigValue, dsigValue.length);
            return this;
        }

        Builder embedGSOutput(GSRSSSignatureOutput output) {
            this.gsAccumulator = output.getAccumulatorValue();
            this.gsDsigValue = output.getDSigValue();
            for (GLRSSSignedPart part : parts) {
                part.gsProof = output.getProof(part.toGSIdentifier());
            }
            return this;
        }

        public GLRSSSignatureOutput build() {
            return new GLRSSSignatureOutput(Arrays.asList(parts), gsAccumulator, gsDsigValue);
        }
    }


    public static class GLRSSSignedPart {

        private byte[] messagePart;
        private byte[] randomValue;
        private byte[] accumulatorValue;
        private byte[] gsProof;
        private boolean isRedactable;
        private final List<ByteArray> witnesses = new ArrayList<>();

        public byte[] getMessagePart() {
            return Arrays.copyOf(messagePart, messagePart.length);
        }

        public byte[] getRandomValue() {
            return Arrays.copyOf(randomValue, randomValue.length);
        }

        public byte[] getAccumulatorValue() {
            return Arrays.copyOf(accumulatorValue, accumulatorValue.length);
        }

        public byte[] getGsProof() {
            return Arrays.copyOf(gsProof, gsProof.length);
        }

        public List<ByteArray> getWitnesses() {
            return Collections.unmodifiableList(witnesses);
        }

        public boolean isRedactable() {
            return isRedactable;
        }

        private Identifier toGSIdentifier() {
            return new Identifier(concat(messagePart, accumulatorValue, randomValue));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }

            if (!(o instanceof GLRSSSignedPart)) {
                return false;
            }

            GLRSSSignedPart that = (GLRSSSignedPart) o;

            return isRedactable == that.isRedactable
                    && Arrays.equals(messagePart, that.messagePart)
                    && Arrays.equals(randomValue, that.randomValue)
                    && Arrays.equals(accumulatorValue, that.accumulatorValue)
                    && witnesses.equals(that.witnesses);
        }

        @Override
        public int hashCode() {
            int result = Arrays.hashCode(messagePart);
            result = 31 * result + Arrays.hashCode(randomValue);
            result = 31 * result + Arrays.hashCode(accumulatorValue);
            result = 31 * result + (isRedactable ? 1 : 0);
            result = 31 * result + witnesses.hashCode();
            return result;
        }
    }
}

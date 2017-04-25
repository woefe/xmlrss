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

    private final GSRSSSignatureOutput gsrssOutput;
    private final List<GLRSSSignedPart> parts;
    private final Set<ByteArray> messageParts;


    GLRSSSignatureOutput(GSRSSSignatureOutput gsrssOutput, List<GLRSSSignedPart> parts) {
        this.gsrssOutput = gsrssOutput;
        this.parts = parts;
        Set<ByteArray> messageParts = new HashSet<>(size());
        for (GLRSSSignedPart part : parts) {
            messageParts.add(new ByteArray(part.getMessagePart()));
        }
        this.messageParts = Collections.unmodifiableSet(messageParts);
    }

    public GSRSSSignatureOutput getGsrssOutput() {
        return gsrssOutput;
    }

    public List<GLRSSSignedPart> getParts() {
        return Collections.unmodifiableList(parts);
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

    static class Builder {

        private final GLRSSSignedPart[] parts;
        private GSRSSSignatureOutput gsrssSignatureOutput;

        Builder(int size) {
            parts = new GLRSSSignedPart[size];
            for (int i = 0; i < size; i++) {
                parts[i] = new GLRSSSignedPart();
            }
        }

        Builder setMessagePart(int index, byte[] messagePart) {
            parts[index].messagePart = Arrays.copyOf(messagePart, messagePart.length);
            return this;
        }

        Builder setRedactable(int index, boolean isRedactable) {
            parts[index].isRedactable = isRedactable;
            return this;
        }

        Builder setRandomValue(int index, byte[] randomValue) {
            parts[index].randomValue = Arrays.copyOf(randomValue, randomValue.length);
            return this;
        }

        Builder addWittness(int index, byte[] wittness) {
            parts[index].witnesses.add(new ByteArray(Arrays.copyOf(wittness, wittness.length)));
            return this;
        }

        Builder setWitnesses(int index, List<ByteArray> witnesses) {
            for (ByteArray witness : witnesses) {
                addWittness(index, witness.getArray());
            }
            return this;
        }

        Builder setAccValue(int index, byte[] accumulatorValue) {
            parts[index].accumulatorValue = Arrays.copyOf(accumulatorValue, accumulatorValue.length);
            return this;
        }

        Builder setGSRSSOutput(GSRSSSignatureOutput gsrssOutput) {
            this.gsrssSignatureOutput = gsrssOutput;
            return this;
        }

        GLRSSSignatureOutput build() {
            return new GLRSSSignatureOutput(gsrssSignatureOutput, Arrays.asList(parts));
        }
    }


    public static class GLRSSSignedPart {

        private byte[] messagePart;
        private byte[] randomValue;
        private byte[] accumulatorValue;
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

        public List<ByteArray> getWitnesses() {
            return Collections.unmodifiableList(witnesses);
        }

        public boolean isRedactable() {
            return isRedactable;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof GLRSSSignedPart)) return false;

            GLRSSSignedPart that = (GLRSSSignedPart) o;

            if (isRedactable != that.isRedactable) return false;
            if (!Arrays.equals(messagePart, that.messagePart)) return false;
            if (!Arrays.equals(randomValue, that.randomValue)) return false;
            if (!Arrays.equals(accumulatorValue, that.accumulatorValue)) return false;
            return witnesses != null ? witnesses.equals(that.witnesses) : that.witnesses == null;
        }

        @Override
        public int hashCode() {
            int result = Arrays.hashCode(messagePart);
            result = 31 * result + Arrays.hashCode(randomValue);
            result = 31 * result + Arrays.hashCode(accumulatorValue);
            result = 31 * result + (isRedactable ? 1 : 0);
            result = 31 * result + (witnesses != null ? witnesses.hashCode() : 0);
            return result;
        }
    }
}

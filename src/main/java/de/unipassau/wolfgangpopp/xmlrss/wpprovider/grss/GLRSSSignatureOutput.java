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
import java.util.List;

/**
 * @author Wolfgang Popp
 */
public class GLRSSSignatureOutput implements SignatureOutput {

    private final GSRSSSignatureOutput gsrssOutput;
    private final List<GLRSSSignedPart> parts;

    private GLRSSSignatureOutput(GSRSSSignatureOutput gsrssOutput, List<GLRSSSignedPart> parts) {
        this.gsrssOutput = gsrssOutput;
        this.parts = Collections.unmodifiableList(parts);
    }

    public GSRSSSignatureOutput getGsrssOutput() {
        return gsrssOutput;
    }

    public List<GLRSSSignedPart> getParts() {
        return parts;
    }

    @Override
    public boolean contains(byte[] part) {
        // TODO
        return false;
    }

    @Override
    public boolean contains(Identifier identifier) {
        // TODO
        return false;
    }

    @Override
    public boolean containsAll(byte[]... part) {
        // TODO
        return false;
    }

    @Override
    public byte[] getMessagePart(Identifier identifier) {
        // TODO
        return new byte[0];
    }

    @Override
    public byte[] getProof(Identifier identifier) {
        // TODO
        return new byte[0];
    }

    @Override
    public int size() {
        // TODO
        return 0;
    }

    static class Builder {

        private final GLRSSSignedPart[] parts;
        private final int size;
        private GSRSSSignatureOutput gsrssSignatureOutput;

        Builder(int size) {
            this.size = size;
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

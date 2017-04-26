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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public class GSRSSSignatureOutput implements SignatureOutput {
    private final Map<ByteArray, byte[]> signedParts = new HashMap<>();
    private final Map<ByteArray, Boolean> redactableMapping = new HashMap<>();
    private byte[] dSigValue;
    private byte[] accumulatorValue;

    GSRSSSignatureOutput() {

    }

    @Override
    public boolean contains(byte[] part) {
        ByteArray wrapper = new ByteArray(part);
        return signedParts.containsKey(wrapper);
    }

    @Override
    public boolean contains(Identifier identifier) {
        return contains(identifier.getBytes());
    }

    @Override
    public boolean containsAll(byte[]... parts) {
        Set<ByteArray> set = new HashSet<>();
        for (byte[] part : parts) {
            set.add(new ByteArray(part));
        }
        return signedParts.keySet().containsAll(set);
    }

    @Override
    public boolean isRedactable(Identifier identifier) {
        return redactableMapping.get(identifier.getByteArray());
    }

    @Override
    public byte[] getMessagePart(Identifier identifier) {
        if (contains(identifier)) {
            return identifier.getBytes();
        }
        return null;
    }

    @Override
    public byte[] getProof(Identifier identifier) {
        return signedParts.get(identifier.getByteArray());
    }

    @Override
    public int size() {
        return signedParts.size();
    }

    public byte[] getDSigValue() {
        return Arrays.copyOf(dSigValue, dSigValue.length);
    }

    public byte[] getAccumulatorValue() {
        return Arrays.copyOf(accumulatorValue, accumulatorValue.length);
    }

    public Set<ByteArray> getNonRedactableParts() {
        Set<ByteArray> nonRedactableParts = new HashSet<>();
        for (Map.Entry<ByteArray, Boolean> part : redactableMapping.entrySet()) {
            if (!part.getValue()) {
                nonRedactableParts.add(part.getKey());
            }
        }
        return Collections.unmodifiableSet(nonRedactableParts);
    }

    public Map<ByteArray, byte[]> getParts() {
        return Collections.unmodifiableMap(signedParts);
    }


    public static class Builder {
        private final GSRSSSignatureOutput signatureOutput = new GSRSSSignatureOutput();

        public Builder setAccumulatorValue(byte[] accumulatorValue) {
            signatureOutput.accumulatorValue = accumulatorValue;
            return this;
        }

        public Builder setDSigValue(byte[] dSigValue) {
            signatureOutput.dSigValue = dSigValue;
            return this;
        }

        public Builder addSignedPart(ByteArray value, byte[] proof, boolean isRedactable) {
            signatureOutput.signedParts.put(value, proof);
            signatureOutput.redactableMapping.put(value, isRedactable);
            return this;
        }

        public GSRSSSignatureOutput build() {
            if (signatureOutput.dSigValue == null || signatureOutput.accumulatorValue == null) {
                throw new IllegalStateException("Either the accumulator value or the dsig value are not set");
            }

            return signatureOutput;
        }
    }
}

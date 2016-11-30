/*
 * XMLRSS - A Java Crypto Provider for Redactable Signatures and their
 * XML Signature encoding.
 *
 * Copyright (c) 2016 Wolfgang Popp
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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public final class PSSignatureOutput implements SignatureOutput, Iterable<PSSignatureOutput.SignedPart> {
    private final Set<SignedPart> set;
    private final byte[] tag;
    private final byte[] proofOfTag;
    private final byte[] accumulator;

    //TODO rename proof to witness

    private PSSignatureOutput(byte[] tag, byte[] proofOfTag, byte[] accumulator) {
        this.tag = tag;
        this.proofOfTag = proofOfTag;
        this.accumulator = accumulator;
        this.set = new HashSet<>();
    }

    /**
     * Returns the tag of this <code>SignedSet</code>.
     *
     * @return the tag
     */
    public byte[] getTag() {
        return Arrays.copyOf(tag, tag.length);
    }

    /**
     * Returns the proof of the tag.
     *
     * @return the proof
     */
    public byte[] getProofOfTag() {
        return Arrays.copyOf(proofOfTag, proofOfTag.length);
    }

    /**
     * Returns the accumulator of this set.
     *
     * @return the accumulator
     */
    public byte[] getAccumulator() {
        return Arrays.copyOf(accumulator, accumulator.length);
    }

    /**
     * Checks if all elements of the given collection are values of this <code>SignedSet</code>.
     *
     * @param c collection to be checked for containment in this set.
     * @return true if all elements of <code>c</code> are values of this set.
     */
    public boolean containsAll(Collection<PSMessagePart> c) {
        return values().containsAll(c);
    }

    /**
     * Checks if the given collection and the values of this <code>SignedSet</code> are disjoint.
     *
     * @param c collection that is checked to be disjoint
     * @return true if all elements of <code>c</code> are not values of this set.
     */
    public boolean isDisjoint(Collection<PSMessagePart> c) {
        return Collections.disjoint(c, values());
    }

    public int size(){
        return set.size();
    }
    /**
     * Returns the values of this <code>SignedSet</code>.
     *
     * @return the set of values without their corresponding proofs
     */
    public Set<PSMessagePart> values() {
        Set<PSMessagePart> resultSet = new HashSet<>();
        for (SignedPart elem : set) {
            resultSet.add(elem.getElement());
        }
        return resultSet;
    }

    private PSSignatureOutput copy() {
        PSSignatureOutput outputSet = new PSSignatureOutput(getTag(), getProofOfTag(), getAccumulator());
        for (SignedPart element : set) {
            outputSet.set.add(element);
        }
        return outputSet;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<SignedPart> iterator() {
        return set.iterator();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PSSignatureOutput that = (PSSignatureOutput) o;

        return set.equals(that.set)
                && Arrays.equals(getTag(), that.getTag())
                && Arrays.equals(getProofOfTag(), that.getProofOfTag())
                && Arrays.equals(getAccumulator(), that.getAccumulator());

    }

    @Override
    public int hashCode() {
        int result = set.hashCode();
        result = 31 * result + Arrays.hashCode(getTag());
        result = 31 * result + Arrays.hashCode(getProofOfTag());
        result = 31 * result + Arrays.hashCode(getAccumulator());
        return result;
    }

    /**
     * This builder creates a new {@link PSSignatureOutput}.
     */
    static class Builder {
        private PSSignatureOutput psSignatureOutput;

        /**
         * Creates a new Builder, which is initialized with an empty {@link PSSignatureOutput}.
         *
         * @param tag         the randomly generated tag for the <code>SignedSet</code>
         * @param proofOfTag  the proof corresponding to the tag
         * @param accumulator the accumulator of the <code>SignedSet</code>
         */
        public Builder(byte[] tag, byte[] proofOfTag, byte[] accumulator) {
            psSignatureOutput = new PSSignatureOutput(tag, proofOfTag, accumulator);
        }

        /**
         * Creates a new <code>Builder</code>, which is initialized with the given {@link PSSignatureOutput}. The
         * <code>Builder</code> does not modify the given set, but creates a new copy of it.
         *
         * @param signedSet the <code>SignedSet</code> that initializes this builder
         */
        public Builder(PSSignatureOutput signedSet) {
            this.psSignatureOutput = signedSet.copy();
        }


        /**
         * Adds the given part together with its proof to the {@link PSSignatureOutput}.
         *
         * @param part the part that is add to the set
         * @param proof the proof corresponding to the given part
         * @return a reference to this object
         */
        public Builder add(byte[] part, byte[] proof) {
            add(new SignedPart(proof, new PSMessagePart(part)));
            return this;
        }

        /**
         * Adds a new {@link SignedPart} to the {@link PSSignatureOutput}.
         *
         * @param element the element that is added to the set
         * @return a reference to this object
         */
        public Builder add(SignedPart element) {
            psSignatureOutput.set.add(element);
            return this;
        }

        public Builder addAll(PSSignatureOutput signature) {
            psSignatureOutput.set.addAll(signature.set);
            return this;
        }

        public Builder addAll(Collection<SignedPart> elements) {
            psSignatureOutput.set.addAll(elements);
            return this;
        }

        /**
         * Constructs a {@link PSSignatureOutput} from the components in this builder.
         *
         * @return a new <code>{@link PSSignatureOutput}</code>
         */
        public PSSignatureOutput build() {
            return psSignatureOutput;
        }
    }

    static class SignedPart {
        private final byte[] proof;
        private final PSMessagePart part;

        SignedPart(byte[] proof, PSMessagePart part) {
            this.proof = proof;
            this.part = part;
        }

        public byte[] getProof() {
            return proof;
        }

        public PSMessagePart getElement() {
            return part;
        }
    }
}
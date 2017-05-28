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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

/**
 * The <code>AccumulatorState</code> is a container for various values that are necessary to restore the state of an
 * {@link Accumulator}. Algorithm specific subclasses of this container may add additional values, but it must always be
 * possible to restore an accumulator from the accumulator value, the auxiliary value and the accumulated elements. Any
 * other additional values should be used to improve performance of accumulator restoration.
 *
 * @author Wolfgang Popp
 */
public class AccumulatorState {

    public final byte[] accumulatorValue;
    public final byte[] auxiliaryValue;
    public final byte[][] elements;

    /**
     * Constructs a new AccumulatorState from the given values and elements
     *
     * @param accumulatorValue the accumulator value generated from the given elements
     * @param auxiliaryValue   the auxiliary value used by the accumulator
     * @param elements         the elements used to create the accumulator value
     */
    public AccumulatorState(byte[] accumulatorValue, byte[] auxiliaryValue, byte[]... elements) {
        this.accumulatorValue = accumulatorValue;
        this.auxiliaryValue = auxiliaryValue;
        this.elements = elements;
    }
}

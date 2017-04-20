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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Wolfgang Popp
 */
public class GLRSSSignedPart {
    private byte[] messagePart;
    private byte[] randomValue;
    private byte[] accumulatorValue;
    private boolean isRedactable;
    private final List<ByteArray> witnesses = new ArrayList<>();

    public byte[] getMessagePart() {
        return messagePart;
    }

    public byte[] getRandomValue() {
        return randomValue;
    }

    public byte[] getAccumulatorValue() {
        return accumulatorValue;
    }

    public List<ByteArray> getWitnesses() {
        return witnesses;
    }

    public boolean isRedactable() {
        return isRedactable;
    }

    void setMessagePart(byte[] messagePart) {
        this.messagePart = messagePart;
    }

    void setRandomValue(byte[] randomValue) {
        this.randomValue = randomValue;
    }

    void setAccumulatorValue(byte[] accumulatorValue) {
        this.accumulatorValue = accumulatorValue;
    }

    void setRedactable(boolean redactable) {
        this.isRedactable = redactable;
    }
}

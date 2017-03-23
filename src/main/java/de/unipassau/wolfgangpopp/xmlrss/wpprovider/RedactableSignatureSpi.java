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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;

public abstract class RedactableSignatureSpi {

    protected abstract void engineInitSign(KeyPair keyPair) throws InvalidKeyException;

    protected abstract void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException;

    protected abstract void engineInitVerify(PublicKey publicKey) throws InvalidKeyException;

    protected abstract void engineInitRedact(PublicKey publicKey) throws InvalidKeyException;

    protected void engineInitMerge(PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support merging");
    }

    ;

    protected void engineInitUpdate(KeyPair privateKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support updating");
    }

    protected abstract void engineAddPart(byte[] part, boolean admissible) throws RedactableSignatureException;

    //protected abstract void engineAddAllAdmissibleParts(byte[]... parts) throws SignatureException;
    //protected abstract void engineAddAllNonAdmissibleParts(byte[]... parts) throws SignatureException;
    //protected abstract void engineAddAllAdmissibleParts(Collection<byte[]> parts) throws SignatureException;
    //protected abstract void engineAddAllNonAdmissibleParts(Collection<byte[]> parts) throws SignatureException;

    protected abstract SignatureOutput engineSign() throws RedactableSignatureException;

    protected abstract boolean engineVerify(SignatureOutput signature) throws RedactableSignatureException;

    protected abstract SignatureOutput engineRedact(SignatureOutput signature) throws RedactableSignatureException;

    protected SignatureOutput engineMerge(SignatureOutput signature1, SignatureOutput signature2) throws RedactableSignatureException {
        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support merging");
    }

    protected SignatureOutput engineUpdate(SignatureOutput original) throws RedactableSignatureException {
        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support updating");
    }

    protected abstract void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException;

    protected abstract AlgorithmParameters engineGetParameters();

}

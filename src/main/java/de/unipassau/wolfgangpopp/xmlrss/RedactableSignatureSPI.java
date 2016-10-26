package de.unipassau.wolfgangpopp.xmlrss;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

public abstract class RedactableSignatureSPI {

    protected SecureRandom appRandom = null;

    protected abstract void engineInitSign(PublicKey publicKey) throws InvalidKeyException;

    protected abstract void engineAddPart(byte[] part, boolean admissible) throws SignatureException;

    protected abstract SignatureOutput engineSign() throws SignatureException;


    protected abstract void engineInitVerify(PublicKey publicKey) throws InvalidKeyException;

    protected abstract boolean engineVerify(SignatureOutput signature) throws SignatureException;


    protected abstract void engineInitRedact(PublicKey publicKey /*TODO*/) throws InvalidKeyException;
    protected abstract SignatureOutput engineRedact(SignatureOutput signature) throws SignatureException;

}

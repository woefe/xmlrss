package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.IllegalModificationException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.ModificationInstruction;

import java.util.HashSet;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public class PSModificationInstruction extends ModificationInstruction {

    private final HashSet<PSMessagePart> parts = new HashSet<>();

    @Override
    public void add(byte[] part) throws IllegalModificationException {
        if (!parts.add(new PSMessagePart(part))) {
            throw new IllegalModificationException("Duplicates are not allowed");
        }
    }

    Set<PSMessagePart> getParts() {
        return parts;
    }
}

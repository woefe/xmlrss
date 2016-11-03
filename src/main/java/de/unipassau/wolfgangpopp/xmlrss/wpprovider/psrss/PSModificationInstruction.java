package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.ModificationInstruction;

import java.util.HashSet;

/**
 * @author Wolfgang Popp
 */
public class PSModificationInstruction extends HashSet<PSMessagePart> implements ModificationInstruction {

    public boolean add(byte[] part) {
        return super.add(new PSMessagePart(part));
    }
}

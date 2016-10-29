package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import java.security.GeneralSecurityException;

/**
 * @author Wolfgang Popp
 */
public class AccumulatorException extends GeneralSecurityException {

    public AccumulatorException() {
        super();
    }

    public AccumulatorException(String message) {
        super(message);
    }

    public AccumulatorException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccumulatorException(Throwable cause) {
        super(cause);
    }
}

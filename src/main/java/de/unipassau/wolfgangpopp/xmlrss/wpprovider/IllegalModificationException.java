package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

/**
 * @author Wolfgang Popp
 */
public class IllegalModificationException extends Exception {
    public IllegalModificationException() {
    }

    public IllegalModificationException(String message) {
        super(message);
    }

    public IllegalModificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public IllegalModificationException(Throwable cause) {
        super(cause);
    }

    public IllegalModificationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}

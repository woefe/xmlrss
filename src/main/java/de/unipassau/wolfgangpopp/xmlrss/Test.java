package de.unipassau.wolfgangpopp.xmlrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * @author Wolfgang Popp
 */
public class Test {

    public static void main(String[] args) {

        Security.insertProviderAt(new WPProvider(), 0);

        RedactableSignature rss = null;
        try {
            rss = RedactableSignature.getInstance("TestDummy", "WP");
            rss.initSign(null);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }


    }
}

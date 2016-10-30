package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableSignatureTest {
    static {
        Security.insertProviderAt(new WPProvider(), 0);
    }

    @Test
    public void engineInitSign() throws Exception {

    }

    @Test
    public void engineInitSign1() throws Exception {

    }

    @Test
    public void engineInitVerify() throws Exception {

    }

    @Test
    public void engineInitRedact() throws Exception {

    }

    @Test
    public void engineInitMerge() throws Exception {

    }

    @Test
    public void engineInitUpdate() throws Exception {

    }

    @Test
    public void engineAddPart() throws Exception {

    }

    @Test
    public void engineSign() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("PSRSS");
        generator.initialize(512);
        KeyPair keyPair = generator.generateKeyPair();

        RedactableSignature rssWithPSA = RedactableSignature.getInstance("RSSwithPSA");
        rssWithPSA.initSign(keyPair);

        rssWithPSA.addPart("test".getBytes(), false);
        rssWithPSA.addPart("test2".getBytes(), false);

        SignatureOutput signature = rssWithPSA.sign();

        rssWithPSA.initVerify(keyPair.getPublic());
        assertTrue(rssWithPSA.verify(signature));

    }

    @Test
    public void engineVerify() throws Exception {

    }

    @Test
    public void engineRedact() throws Exception {

    }

    @Test
    public void engineMerge() throws Exception {

    }

    @Test
    public void engineUpdate() throws Exception {

    }

    @Test
    public void engineSetParameters() throws Exception {

    }

    @Test
    public void engineGetParameters() throws Exception {

    }

}
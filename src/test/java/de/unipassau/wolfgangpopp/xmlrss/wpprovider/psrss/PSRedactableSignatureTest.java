package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.ModificationInstruction;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableSignatureTest {

    private static KeyPair keyPair;

    static {
        Security.insertProviderAt(new WPProvider(), 0);
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("PSRSS");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        generator.initialize(512);
        keyPair = generator.generateKeyPair();
    }


    public PSRedactableSignatureTest() throws NoSuchAlgorithmException {
    }

    @Test(expected = SignatureException.class)
    public void getInstance() throws Exception{
        RedactableSignature rss1 = RedactableSignature.getInstance("RSSwithPSA");

        try {
            rss1.initVerify(keyPair.getPublic());
            rss1.addPart("test".getBytes(), false);
        } catch (Exception e) {
            throw new Exception(e);
        }

        rss1 = RedactableSignature.getInstance("RSSwithPSA");
        rss1.addPart("asdf".getBytes(), false);
    }

    @Test
    public void engineSign() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance("RSSwithPSA");
        rssWithPSA.initSign(keyPair);

        rssWithPSA.addPart("test".getBytes(), false);
        rssWithPSA.addPart("test2".getBytes(), false);

        SignatureOutput signature = rssWithPSA.sign();

        assertNotNull(signature);
    }

    @Test
    public void engineVerify() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance("RSSwithPSA");
        rssWithPSA.initSign(keyPair);

        rssWithPSA.addPart("test3".getBytes(), false);
        rssWithPSA.addPart("test2".getBytes(), false);
        rssWithPSA.addPart("test4".getBytes(), false);

        SignatureOutput signature = rssWithPSA.sign();

        rssWithPSA.initVerify(keyPair.getPublic());
        assertTrue(rssWithPSA.verify(signature));
    }

    @Test
    public void engineRedact() throws Exception {
        ModificationInstruction mod = ModificationInstruction.forAlgorithm("RSSwithPSA");
        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");
        rss.initSign(keyPair);

        rss.addPart("test1".getBytes(), false);
        rss.addPart("test2".getBytes(), false);
        rss.addPart("test3".getBytes(), false);
        rss.addPart("test4".getBytes(), false);
        rss.addPart("test5".getBytes(), false);

        SignatureOutput wholeMessage = rss.sign();

        rss.initRedact(keyPair.getPublic());
        mod.add("test4".getBytes());
        mod.add("test5".getBytes());
        SignatureOutput redacted1 = rss.redact(wholeMessage, mod);

        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(redacted1));
    }

    @Test
    public void engineMerge() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");
        rss.initSign(keyPair);

        rss.addPart("test1".getBytes(), false);
        rss.addPart("test2".getBytes(), false);
        rss.addPart("test3".getBytes(), false);
        rss.addPart("test4".getBytes(), false);
        rss.addPart("test5".getBytes(), false);

        SignatureOutput wholeMessage = rss.sign();

        rss.initRedact(keyPair.getPublic());
        ModificationInstruction mod = ModificationInstruction.forAlgorithm(rss);
        mod.add("test4".getBytes());
        mod.add("test5".getBytes());
        SignatureOutput redacted1 = rss.redact(wholeMessage, mod);

        rss = RedactableSignature.getInstance("RSSwithPSA");
        rss.initRedact(keyPair.getPublic());
        mod = ModificationInstruction.forAlgorithm(rss);
        mod.add("test2".getBytes());
        mod.add("test3".getBytes());
        SignatureOutput redacted2 = rss.redact(wholeMessage, mod);

        rss.initMerge(keyPair.getPublic());
        rss.merge(redacted1, redacted2);

    }

    @Test
    public void engineUpdate() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");

        rss.initSign(keyPair);
        rss.addPart("test1".getBytes(), false);
        rss.addPart("test2".getBytes(), false);
        rss.addPart("test3".getBytes(), false);
        SignatureOutput wholeMessage = rss.sign();

        rss.initUpdate(keyPair);
        rss.addPart("test4".getBytes(), false);
        rss.addPart("test5".getBytes(), false);
        SignatureOutput updated = rss.update(wholeMessage);

        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(updated));
    }
}
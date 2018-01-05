package com.soriole.wallet.sqrapp.bitcoin;

import com.soriole.wallet.lib.ByteUtils;
import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.lib.exceptions.ValidationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.security.*;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

/**
 * Adapted from https://github.com/bitsofproof/supernode/blob/1.1/api/src/main/java/com/bitsofproof/supernode/api/ExtendedKey.java
 */

public class BitcoinExtendedKeyTest {
    private final SecureRandom random = new SecureRandom();

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerator() throws ValidationException {
        BitcoinExtendedKey ekprivate = BitcoinExtendedKey.createNew();
        BitcoinExtendedKey ekpublic = new BitcoinExtendedKey(ECKeyPair.publicOnly(ekprivate.getMaster().getPublic(), true), ekprivate.getChainCode(), 0, 0, 0);

        for (int i = 0; i < 20; ++i) {
            ECKeyPair fullControl = ekprivate.getKey(i);
            ECKeyPair readOnly = ekpublic.getKey(i);

            assertTrue(Arrays.equals(fullControl.getPublic(), readOnly.getPublic()));
            assertTrue(Arrays.equals(fullControl.getAddress(), readOnly.getAddress()));

            byte[] toSign = new byte[100];
            random.nextBytes(toSign);

            byte[] signature = fullControl.sign(toSign);
            assertTrue(readOnly.verify(toSign, signature));
        }

    }

    private static final ThreadMXBean mxb = ManagementFactory.getThreadMXBean();
    private static final Logger log = LoggerFactory.getLogger(BitcoinExtendedKeyTest.class);

    private JSONArray readObjectArray(String resource) throws IOException, JSONException {
        InputStream input = this.getClass().getResource("/" + resource).openStream();
        StringBuffer content = new StringBuffer();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = input.read(buffer)) > 0) {
            byte[] s = new byte[len];
            System.arraycopy(buffer, 0, s, 0, len);
            content.append(new String(buffer, "UTF-8"));
        }
        return new JSONArray(content.toString());
    }

    @Test
    public void testBip32() throws IOException, JSONException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ValidationException {
        JSONArray tests = readObjectArray("BIP32.json");
        for (int i = 0; i < tests.length(); ++i) {
            JSONObject test = tests.getJSONObject(i);

            BitcoinExtendedKey ekprivate = BitcoinExtendedKey.create(ByteUtils.fromHex(test.getString("seed")));
            BitcoinExtendedKey ekpublic = ekprivate.getReadOnly();

            assertTrue(ekprivate.serialize(true).equals(test.get("private")));
            assertTrue(ekpublic.serialize(true).equals(test.get("public")));

            JSONArray derived = test.getJSONArray("derived");
            for (int j = 0; j < derived.length(); ++j) {
                JSONObject derivedTest = derived.getJSONObject(j);
                JSONArray locator = derivedTest.getJSONArray("locator");
                BitcoinExtendedKey ek = ekprivate;
                BitcoinExtendedKey ep = ekpublic;
                for (int k = 0; k < locator.length(); ++k) {
                    JSONObject c = locator.getJSONObject(k);
                    if (!c.getBoolean("private")) {
                        ek = ek.getChild(c.getInt("sequence"));
                    } else {
                        ek = ek.getChild(c.getInt("sequence") | 0x80000000);
                    }
                    ep = ek.getReadOnly();
                }

                assertTrue(ek.serialize(true).equals(derivedTest.getString("private")));
                assertTrue(ep.serialize(true).equals(derivedTest.getString("public")));
            }
        }
    }

    @Test
    public void testBip32Passphrase() throws ValidationException, JSONException, IOException {
        JSONArray tests = readObjectArray("PassphraseKey.json");
        for (int i = 0; i < tests.length(); ++i) {
            JSONObject test = tests.getJSONObject(i);
            BitcoinExtendedKey key = BitcoinExtendedKey.createFromPassphrase(test.getString("passphrase"), ByteUtils.fromHex(test.getString("seed")));
            assertTrue(key.serialize(true).equals(test.get("key")));
        }
    }

    @Test
    public void testECDSASpeed() throws ValidationException {
        ECKeyPair key = ECKeyPair.createNew(true);
        byte[] data = new byte[32];
        random.nextBytes(data);
        byte[] signature = key.sign(data);
        long cpu = -mxb.getCurrentThreadUserTime();
        for (int i = 0; i < 100; ++i) {
            assertTrue(key.verify(data, signature));
        }
        cpu += mxb.getCurrentThreadUserTime();
        double speed = 100.0 / (cpu / 10.0e9);
        log.info("ECDSA validation speed : " + speed + " signatures/second");
        assertTrue(speed > 100.0);
    }
}

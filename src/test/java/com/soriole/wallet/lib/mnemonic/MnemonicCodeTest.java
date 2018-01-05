package com.soriole.wallet.lib.mnemonic;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class MnemonicCodeTest {
    private static final Logger log = LoggerFactory.getLogger(MnemonicCodeTest.class);
    private final SecureRandom random = new SecureRandom();

    private static final String BIP39_ENGLISH_RESOURCE_NAME = "mnemonic/wordlist/english.txt";
    private static final String BIP39_ENGLISH_SHA256 = "ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db";

    @Test
    public void testMnemonicCode() throws IOException, MnemonicException.MnemonicLengthException, MnemonicException.MnemonicChecksumException, MnemonicException.MnemonicWordException {
        byte[] randomSeed = new byte[32];
        random.nextBytes(randomSeed);

        InputStream stream = this.getClass().getResource("/" + BIP39_ENGLISH_RESOURCE_NAME).openStream();
        MnemonicCode mnemonicCode = new MnemonicCode(stream, BIP39_ENGLISH_SHA256);
        List<String> seedWords = mnemonicCode.toMnemonic(randomSeed);
        log.info("Testcase seed words:{}", seedWords);

        // recover the seed from seed words
        byte[] recoveredSeed = mnemonicCode.toEntropy(seedWords);
        assertTrue(Arrays.equals(randomSeed, recoveredSeed));
    }
}

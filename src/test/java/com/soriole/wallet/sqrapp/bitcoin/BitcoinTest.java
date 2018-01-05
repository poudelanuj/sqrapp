package com.soriole.wallet.sqrapp.bitcoin;

import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.lib.exceptions.ValidationException;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class BitcoinTest {
    private Bitcoin instance;

    public BitcoinTest() {
        instance = new Bitcoin();
    }

    @Test
    public void testWIF() throws ValidationException {
        String privateKeyHex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
        String privateKeyWif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

        BigInteger privateKey = new BigInteger(privateKeyHex, 16);
        String computedWif = instance.serializeWIF(ECKeyPair.create(privateKey));
        assertEquals(privateKeyWif, computedWif);

        ECKeyPair keyPair = instance.parseWIF(privateKeyWif);
        BigInteger privateKeyFromWif = keyPair.getPrivateKey();
        assertEquals(privateKey, privateKeyFromWif);
    }

    @Test
    public void testAddress() throws ValidationException {
        String address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
        String privateKeyStr = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";

        BigInteger privateKey = new BigInteger(privateKeyStr, 16);
        ECKeyPair keyPair = ECKeyPair.create(privateKey);

        byte[] pubBytes = keyPair.getPublic();
        String computedAddress = instance.address(pubBytes);
        assertEquals(address, computedAddress);
    }
}

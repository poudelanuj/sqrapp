package com.soriole.wallet.lib;

import org.hamcrest.core.IsEqual;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

public class WIFTest {
    @Test
    public void TestWIF() throws WIF.InvalidWIFException {
        SecureRandom random =new SecureRandom();
        byte[] testBytes=new byte[32];
        random.nextBytes(testBytes);
        String inputHex=ByteUtils.toHex(testBytes);
        String wif=WIF.encode(testBytes);
        byte[] outptBytes=WIF.decode(wif);
        String outHex=ByteUtils.toHex(outptBytes);
        if(!inputHex.equals(outHex)){
            System.err.println("Input Byte : "+inputHex);
            System.err.println("WIF value  : "+wif);
            System.err.println("Output Byte: "+outHex);
            assert(false);
        }
    }
}

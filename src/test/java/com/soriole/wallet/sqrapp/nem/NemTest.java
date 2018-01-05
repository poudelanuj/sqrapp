package com.soriole.wallet.sqrapp.nem;
import com.soriole.wallet.lib.ByteUtils;
import org.apache.commons.io.FileUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;

/**
 * @author github.com/mesudip
 * Public key and Wallet Address generation test for Nem Wallet implementaion
 *
 */
public class NemTest {
    Nem nem;
    JSONArray testArray;

    /**
     *  Loads Nem wallet data from json file in resource folder
     * @throws IOException
     * @throws JSONException
     */
    public NemTest() throws IOException, JSONException {
        nem=new Nem();
        ClassLoader classLoader = getClass().getClassLoader();
        URL nemWalletJsonURL=classLoader.getResource("wallets/nemWallet.json");
        File file=new File(nemWalletJsonURL.getFile());
        testArray= new   JSONArray(FileUtils.readFileToString(file,"UTF-8"));
    }

    /**
     * From the each wallet info in test array,
     *  i)   takes private key
     *  ii)  computes public key using private key
     *  iii) compares generated public key with the one given in standard data
     *
     * @throws JSONException
     */
    @Test
    public void testPublicKey() throws JSONException{
        boolean success=true;
        for(int i=0;i<testArray.length();i++){
            JSONObject nemWallet=testArray.getJSONObject(i);

            String privateKey=nemWallet.getString("private");
            String publicKey=nemWallet.getString("public");

            byte[] privateByte= ByteUtils.fromHex(privateKey);

            byte[] obtainedpublicByte=nem.publicKey(privateByte);

            String obtainedPublicKey=ByteUtils.toHex(obtainedpublicByte);

            if(!obtainedPublicKey.equals(publicKey)){
                if(success){
                    System.err.println("Errors for Nem Public Key Test");
                    success=false;
                }
                System.err.println("Expected :"+publicKey);
                System.err.println("Obtained :"+obtainedPublicKey);
            }
        }
        assert(success);
    }

    /**
     * From the each wallet info in test array,
     *  i)   takes public key
     *  ii)  generates wallet address from the key
     *  iii) compares generated wallet address with the standard one.
     *
     * @throws JSONException
     */

    @Test
    public void testAddress() throws JSONException {
        boolean success=true;
        for(int i=0;i<testArray.length();i++){
            JSONObject nemWallet=testArray.getJSONObject(i);


            String publicKey=nemWallet.getString("public");
            String address=nemWallet.getString("address");

            byte[] publicByte= ByteUtils.fromHex(publicKey);

            String obtainedAddress=nem. getAddress(publicByte);
            if(!obtainedAddress.equals(address)){
                if(success){
                    System.err.println("Errors for Nem Address generation  Test");
                    success=false;
                }
                System.err.println("Expected :"+address);
                System.err.println("Obtained :"+obtainedAddress);
            }
        }
        assert(success);

    }
}
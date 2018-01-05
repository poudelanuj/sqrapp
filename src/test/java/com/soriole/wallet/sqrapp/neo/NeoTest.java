package com.soriole.wallet.sqrapp.neo;

import com.soriole.wallet.lib.ByteUtils;
import com.soriole.wallet.lib.WIF;
import com.soriole.wallet.lib.WIFTest;
import com.soriole.wallet.lib.exceptions.ValidationException;
import org.apache.commons.io.FileUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * @author github.com/mesudip
 * Public Key and Wallet Address generation test for Neo wallet implementation
 */
public class NeoTest {

    private Neo neo;
    JSONArray testArray;

    public NeoTest() throws IOException, JSONException {
        neo = new Neo();

        ClassLoader classLoader = getClass().getClassLoader();
        URL nemWalletJsonURL=classLoader.getResource("wallets/neoWallet.json");
        File file=new File(nemWalletJsonURL.getFile());
        testArray= new   JSONArray(FileUtils.readFileToString(file,"UTF-8"));

    }

    /**
     * <strong>Performs following:</strong>
     * <ol>
     *    <li>read private wif from json data</li>
     *    <li>extract private key from it</li>
     *    <li>generate public key using the private key</li>
     *    <li>compare generated public key with the standard one</li>
     * </ol>
     * @throws ValidationException
     * @throws IOException
     * @throws JSONException
     * @throws WIF.InvalidWIFException
     */
    @Test
    public void testAddress() throws ValidationException, IOException, JSONException, WIF.InvalidWIFException {
        boolean success=true;
        // iterate over each data for testing
        for(int i=0;i<testArray.length();i++){
            // get i'th data in the array
            JSONObject wallet= (JSONObject) testArray.get(i);

            // get public key  from the data
            byte[] publicKey= ByteUtils.fromHex(wallet.getString("public"));

            // from private key generate wallet address.
            String address=neo.getAddress(publicKey);

            // from the test data, obtain expected wallet address
            String correctAddress=wallet.getString("address");

            // now compare them. even if it is error, keep testing on  other data.
            if(!address.equals(correctAddress)){
                if(success) {
                    System.err.println("Neo Wallet Address Test");
                    success=false;
                }
                System.err.println("Expected : " + correctAddress);
                System.err.println("Got      : " + address);
            }
        }
        assert(success);
    }

    /**
     *  For each wallet data in the test array,
     *  Performs following.
     *  i)   takes public key
     *  ii)  generates wallet address from the key
     *  iii) compares generated wallet address with the standard one.
     *
     * @throws ValidationException
     * @throws JSONException
     * @throws WIF.InvalidWIFException
     */
    @Test
    public void testPublicKey() throws ValidationException, JSONException, WIF.InvalidWIFException {
        boolean success=true;

        // iterate over each test data in json array
        for(int i=0;i<testArray.length();i++){
            // get i'th data in array
            JSONObject wallet= testArray.getJSONObject(i);

            // get WIF string from data
            String wif= wallet.getString("privatewif");

            // find public key from WIF string
            byte[] privateKey= WIF.decode(wif);

            // use EC and to find public key
            byte[] publicKey=neo.publicKey(privateKey);

            // Convert bytes into hex string so that may be printed if error occurs.
            // the obtained public key byteString
            String publicKeyString=ByteUtils.toHex(publicKey);

            // the exptected public key byteString
            String correctPublicKeyString=wallet.getString("public");

            // now if there's error, check all other inputs and report error.
            if(!publicKeyString.equals(correctPublicKeyString)){
                if (success){
                    System.err.println("Neo Public Key Test");
                    success=false;
                }
                System.err.println("Expected : " + correctPublicKeyString);
                System.err.println("Got      : " + publicKeyString);

            }
        }
        assert(success);

    }
}

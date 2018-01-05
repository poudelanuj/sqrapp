package com.soriole.wallet.lib;

import org.bitcoinj.core.Base58;
import org.bouncycastle.jcajce.provider.digest.SHA256;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class WIF {
    static public class InvalidWIFException extends Exception{ }
    static public byte[] decode(String WIF)throws InvalidWIFException{
        byte[] wif=Base58.decode(WIF);
        // extended key= WIF - last 4 checksum bytes
        byte[] extendedKey=Arrays.copyOf(wif,wif.length-4);

        // the fist byte in the extended key must be 0x80 for main Network.
        /// similarly the last byte should be 0x01
        if(extendedKey[0]!=(byte)0x80 || extendedKey[extendedKey.length-1]!=0x01){
            throw new InvalidWIFException();
        }

        // now the private key is obtained by removing the first and last byte from extended key.
        byte[] privateKey=Arrays.copyOfRange(extendedKey,1,extendedKey.length-1);

        // but we are not done yet!
        // let's check whether or not the checksum is correct.
        try {
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            byte[] digested=digest.digest(digest.digest(extendedKey));
            if(digested[3]!=wif[wif.length-1] ||
               digested[2]!=wif[wif.length-2] ||
               digested[1]!=wif[wif.length-3] ||
               digested[0]!=wif[wif.length-4]){
                throw new InvalidWIFException();
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Cannot get Instance of SHA-256 digest");
        }
        // if all is well return private key as byte array
        return privateKey;
    }
    static public String encode(byte[] privateKey){

        // two bytes for appending 0x80 and 0x01 to private key
        // 4 bytes for checksum at the length.
        byte[] WIFByte=new byte[privateKey.length+2+4];

        try {
            // get sha256 instnce
            MessageDigest sha256=MessageDigest.getInstance("SHA-256");

            // now append 0x80 byte for address of main network.
            WIFByte[0]=(byte)0x80;

            // similarly the last byte must be 0x01
            WIFByte[WIFByte.length-5]=(byte)0x01;

            // copy the private key in between those bytes. to get extended key
            for(int i=0;i<privateKey.length;i++){
                WIFByte[i+1]=privateKey[i];
            }

            // now wee need to hash the extended key.
            // since the wifByte has 4 extra bytes at the end, get a copy of it without those bytes.
            byte[] part=Arrays.copyOf(WIFByte,WIFByte.length-4);

            // double hash the obtained part
            byte[] double_hash=sha256.digest(sha256.digest(part));

            // copy 4 bytes of hash at the end of extended key.
            WIFByte[WIFByte.length-1]=double_hash[3];
            WIFByte[WIFByte.length-2]=double_hash[2];
            WIFByte[WIFByte.length-3]=double_hash[1];
            WIFByte[WIFByte.length-4]=double_hash[0];

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Cannot get Instance of SHA-256 digest");
        }
        // :D everythings done.
        return Base58.encode(WIFByte);
    }
}

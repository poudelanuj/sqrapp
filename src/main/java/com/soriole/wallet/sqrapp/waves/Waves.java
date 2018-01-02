package com.soriole.wallet.sqrapp.waves;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.Normalizer;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.whispersystems.curve25519.java.curve_sigs;

import com.soriole.wallet.sqrapp.CryptoCurrency;
import com.wavesplatform.wavesj.Base58;
import com.wavesplatform.wavesj.PrivateKeyAccount;

public class Waves implements CryptoCurrency{
	
	private static final Digest BLAKE2B256 = new Blake2bDigest(256);
    private static final Digest KECCAK256 = new KeccakDigest(256);
    private static final Digest SHA256 = new SHA256Digest();

    @Override
    public byte[] newSeed() {
    	String seedString=PrivateKeyAccount.generateSeed();
    	String mnemonic=Normalizer.normalize(seedString,Normalizer.Form.NFKD);
		final char[] chars = mnemonic.toCharArray();
		byte[] salt = null;
		SecretKeyFactory secretKeyFactory = null;
		PBEKeySpec spec=null;
		
		try {
			salt = ("mnemonic" ).getBytes("UTF-8");
			spec= new PBEKeySpec(chars, salt, 2048, 512);
			secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			return secretKeyFactory.generateSecret(spec).getEncoded();
			
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return null;
		
        
    }

    @Override
    public byte[] newPrivateKey() {
    	MessageDigest messagedigest=null;
		try {
			messagedigest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		messagedigest.reset();
		return messagedigest.digest();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed) {
    	int nonce=0;
		// account seed from seed & nonce
        ByteBuffer buf = ByteBuffer.allocate(seed.length + 4);
        buf.putInt(nonce).put(seed);
        byte[] accountSeed = secureHash(buf.array(), 0, buf.array().length);
        
        // private key from account seed & scheme
        byte[] hashedSeed = hash(accountSeed, 0, accountSeed.length, SHA256);
        byte[] privateKey = Arrays.copyOf(hashedSeed, 32);
        privateKey[0]  &= 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;

        return privateKey;
    }

    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {
    	ByteBuffer buf = ByteBuffer.allocate(seed.length + 4);
        buf.putInt(index).put(seed);
        byte[] accountSeed = secureHash(buf.array(), 0, buf.array().length);

        // private key from account seed & scheme
        byte[] hashedSeed = hash(accountSeed, 0, accountSeed.length, SHA256);
        byte[] privateKey = Arrays.copyOf(hashedSeed, 32);
        privateKey[0]  &= 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;

        return privateKey;
    }

    @Override
    public byte[] publicKey(byte[] privateKey) {
    	byte[] publicKey = new byte[32];
        curve_sigs.curve25519_keygen(publicKey, privateKey); 
        return publicKey;
    }
    
  //static char MAINNET = 'W';
  	//static char TESTNET = 'T';
  	// scheme can be 'W' or 'T' ,W is for mainnet and T is for testnet during address generation
  	public byte[] generateWalletAddress(byte[] publicKey,char scheme) { 
  		ByteBuffer buf = ByteBuffer.allocate(26);
          byte[] hash = secureHash(publicKey, 0, publicKey.length);
          buf.put((byte) 1).put((byte) scheme).put(hash, 0, 20);
          byte[] checksum = secureHash(buf.array(), 0, 22);
          buf.put(checksum, 0, 4);
          return buf.array();
  		
  	}
  	
  	static byte[] secureHash(byte[] message, int ofs, int len) {
  		
          byte[] blake2b = hash(message, ofs, len, BLAKE2B256);
          return hash(blake2b, 0, blake2b.length, KECCAK256);
  	
  	}
  	
  	static byte[] hash(byte[] message, int ofs, int len, Digest alg) {
  		
          byte[] res = new byte[alg.getDigestSize()];
          alg.update(message, ofs, len);
          alg.doFinal(res, 0);
          return res;
          
  	}
  	
  	public static String getString(byte[] bytes) {
  		return Base58.encode(bytes);
  	}
  	

}

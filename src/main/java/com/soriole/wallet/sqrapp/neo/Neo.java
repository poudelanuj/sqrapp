package com.soriole.wallet.sqrapp.neo;

import com.soriole.wallet.lib.ByteUtils;
import com.soriole.wallet.lib.Hashes;
import com.soriole.wallet.sqrapp.CryptoCurrency;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;


/**
 * @author github.com/mesudip
 * <p>Wallet Implementation for NEO CryptoCurrency</p>
 */
public class Neo implements CryptoCurrency {

    static ECDomainParameters secp25641Curve;

    // The curve for Neo wallet is secp25641
    static {
        X9ECParameters curveParams = CustomNamedCurves.getByName("secp256r1");
        if (curveParams==null){
            throw new RuntimeException("Curve secp256r1 implementation not found");
        }
        secp25641Curve = new ECDomainParameters(
                curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH());

    }


    @Override
    // creates a new random seed
    public byte[] newSeed() {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        return seed;
    }

    @Override
    public byte[] newPrivateKey() {
        // well, any random number is a private key.
        return newSeed();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed) {
        return Hashes.sha256(seed);
    }

    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {

        BigInteger repr = new BigInteger(1, seed);
        repr=repr.add(BigInteger.valueOf(index));
        return Hashes.sha256(repr.toByteArray());
    }

    /**
     * @param privateKey byte[]
     * @return byte[] : compressed publicKey
     */
    @Override
    public byte[] publicKey(byte[] privateKey) {
        // get corresponding coordinate for given privatekey on the curve
        ECPoint point = Neo.secp25641Curve.getG().multiply(new BigInteger(1, privateKey));

        // return coordinate as byte array.
        return point.getEncoded(true);
    }

    /**
     * @param publicKey : publicKey byte
     * @return String :Base58 encoded standard Wallet address format
     */

    public String getAddress(byte[] publicKey) {

        // now we need to append 0x21 byte to the start and 0xac byte to the end
        byte[] pk = new byte[publicKey.length + 2];
        pk[0] = (byte) 0x21;
        pk[pk.length - 1] = (byte) 0xac;
        for (int i = 0; i < publicKey.length; i++) {
            pk[i + 1] = publicKey[i];
        }
        // now we have added those bytes to the public key
        // perform sha256 and then ripemd160 consecutively
        byte[] ripemdHash = Hashes.ripemd160(Hashes.sha256(pk));

        // again we need to add as ADDR_VERS infront of RIPEMD ie 0x17
        pk = new byte[ripemdHash.length + 1];
        pk[0] = (byte) 0x17;
        for (int i = 0; i < ripemdHash.length; i++) {
            pk[i + 1] = ripemdHash[i];
        }

        // Now we are done. all we need to do is to add 4 checksum bytes to the end
        // so here's the checksum with double hashing
        byte[] checksum = Hashes.sha256(Hashes.sha256(pk));

        // now address is RIPHashed + checksum[0:4]
        byte[] addressBuffer = new byte[pk.length + 4];
        int i = 0;
        int k = 0;
        for (; i < pk.length; i++)
            addressBuffer[i] = pk[i];

        while (i < addressBuffer.length)
            addressBuffer[i++] = checksum[k++];

        // now we have done making the address.
        // let's present it as bs58 encoded string.
        return ByteUtils.toBase58(addressBuffer);
    }

}

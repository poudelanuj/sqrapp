package com.soriole.wallet.sqrapp.nem;

import com.soriole.wallet.lib.Hashes;
import com.soriole.wallet.sqrapp.CryptoCurrency;
import com.subgraph.orchid.data.Base32;

import org.nem.core.crypto.ed25519.arithmetic.*;
import org.nem.core.utils.ArrayUtils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author github.com/mesudip
 * <p> Wallet implementaion for Nem Cryptocurrency</p>
 */
public class Nem implements CryptoCurrency {

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
     * @param privateKey : privateKey byteArray
     * @return byte[] publicKey
     *
     * Computes public key when private key is given.
     * org.nem.core.cypto.KeyPair() provides a nice looking interface to generate keypairs.
     * this code is copied from different helper functions and interfaces into one.
     */
    @Override
    public byte[] publicKey(byte[] privateKey) {
        BigInteger integer = new BigInteger(1, privateKey);


        // first of all change to little endian byte order
        // The hashing is for achieving better randomness and the clamping prevents small subgroup attacks.
        final byte[] hash = Hashes.sha3_512(ArrayUtils.toByteArray(integer, 32));

        // Prepare the private key's raw value for scalar multiplication.
        final byte[] a = Arrays.copyOfRange(hash, 0, 32);
        a[31] &= 0x7F;
        a[31] |= 0x40;
        a[0] &= 0xF8;

        // a * base point is the public key.
        final Ed25519GroupElement pubKey = Ed25519Group.BASE_POINT.scalarMultiply(new Ed25519EncodedFieldElement(a));

        // verification of signatures will be about twice as fast when pre-calculating
        // a suitable table of group elements.
        return pubKey.encode().getRaw();
    }

    /**
     * @param publicKey : publicKey byte
     * @param version : Version byte (append at the begining)
     * @return String :Base32 encoded standard Wallet address format
     */

    public String getAddress(byte[] publicKey, byte version) {

        // first sha3 digest and then ripemd160 digest of result
        byte[] hash = Hashes.ripemd160(Hashes.sha3_256(publicKey));


        // the address byte consists of version + hash + checkSumOf(version+hash)
        byte[] addressByte = new byte[hash.length + 1 + 4];

        // prefix Version to the hash result
        addressByte[0] = version;

        // add the hash to the addressByte
        for (int i = 0; i < hash.length; i++) {
            addressByte[i + 1] = hash[i];
        }

        // Find checksum of the (version+hash) part of address byte
        byte[] checksum = Hashes.sha3_256(Arrays.copyOf(addressByte, hash.length + 1));

        // append the checksum to the end it's 4 bytes
        int k = 0;
        for (int i = hash.length + 1; i < addressByte.length; i++) {
            addressByte[i] = checksum[k++];
        }

        // encode with base32 and return result
        return Base32.base32Encode(addressByte).toUpperCase();

    }

    /**
     * @param publicKey : publicKey byte
     * @return String :Base32 encoded standard Wallet address format for main net version
     */
    public String getAddress(byte[] publicKey) {
        // the version id for main network is 104
        return (getAddress(publicKey, (byte) 104));
    }

}

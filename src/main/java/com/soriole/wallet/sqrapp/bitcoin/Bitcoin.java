package com.soriole.wallet.sqrapp.bitcoin;

import com.soriole.wallet.lib.ByteUtils;
import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.lib.exceptions.ValidationException;
import com.soriole.wallet.sqrapp.CryptoCurrency;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;

public class Bitcoin implements CryptoCurrency {
    private static final Logger log = LoggerFactory.getLogger(Bitcoin.class);

    private SecureRandom random = new SecureRandom();

    @Override
    public byte[] newSeed() {
        byte[] seed = new byte[32];
        random.nextBytes(seed);
        return seed;
    }

    @Override
    public byte[] newPrivateKey() {
        BitcoinExtendedKey extendedKey = BitcoinExtendedKey.createNew();
        return extendedKey.getMaster().getPrivate();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed) {
        try {
            BitcoinExtendedKey extendedKey = BitcoinExtendedKey.create(seed);
            return extendedKey.getMaster().getPrivate();
        } catch (ValidationException e) {
            log.error("Could not create bitcoin private key", e);
        }
        return null;
    }

    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {
        try {
            BitcoinExtendedKey extendedKey = BitcoinExtendedKey.create(seed);
            return extendedKey.getChild(index).getMaster().getPrivate();
        } catch (ValidationException e) {
            log.error("Could not create bitcoin private key[{}]", index, e);
        }
        return null;
    }

    @Override
    public byte[] publicKey(byte[] privateKey) {
        try {
            ECKeyPair keyPair = new ECKeyPair(privateKey, true);
            return keyPair.getPublic();
        } catch (ValidationException e) {
            log.error("Could not create public key from private key", e);
        }
        return null;
    }

    public String address(byte[] pubBytes){
        if(pubBytes.length == 64){
            byte[] encodedPubBytes = new byte[65];
            encodedPubBytes[0] = 0x04;
            System.arraycopy(pubBytes, 0, encodedPubBytes, 1, pubBytes.length);
            pubBytes = encodedPubBytes;
        }
        byte[] keyHash = ByteUtils.keyHash(pubBytes);
        byte[] keyHashWithVersion = new byte[keyHash.length + 1];
        keyHashWithVersion[0] = 0x00; // version byte
        System.arraycopy(keyHash, 0, keyHashWithVersion, 1, keyHash.length);
        return ByteUtils.toBase58WithChecksum(keyHashWithVersion);
    }

    public ECKeyPair newKeyPair() {
        return ECKeyPair.createNew(true);
    }

    public String serializeWIF(ECKeyPair key) {
        return ByteUtils.toBase58(bytesWIF(key));
    }

    public String serializeWIF(byte[] privateKey){
        return serializeWIF(privateKey, false);
    }

    public String serializeWIF(byte[] privateKey, boolean compressed) {
        return ByteUtils.toBase58(bytesWIF(privateKey, compressed));
    }

    public byte[] bytesWIF(ECKeyPair key) {
        return bytesWIF(key.getPrivate(), key.isCompressed());
    }

    public byte[] bytesWIF(byte[] privateKey, boolean compressed) {
        if (compressed) {
            byte[] encoded = new byte[privateKey.length + 6];
            byte[] ek = new byte[privateKey.length + 2];
            ek[0] = (byte) 0x80;
            System.arraycopy(privateKey, 0, ek, 1, privateKey.length);
            ek[privateKey.length + 1] = 0x01;
            byte[] hash = ByteUtils.hash(ek);
            System.arraycopy(ek, 0, encoded, 0, ek.length);
            System.arraycopy(hash, 0, encoded, ek.length, 4);
            return encoded;
        } else {
            byte[] encoded = new byte[privateKey.length + 5];
            byte[] ek = new byte[privateKey.length + 1];
            ek[0] = (byte) 0x80;
            System.arraycopy(privateKey, 0, ek, 1, privateKey.length);
            byte[] hash = ByteUtils.hash(ek);
            System.arraycopy(ek, 0, encoded, 0, ek.length);
            System.arraycopy(hash, 0, encoded, ek.length, 4);
            return encoded;
        }
    }

    public ECKeyPair parseWIF(String serialized) throws ValidationException {
        byte[] store = ByteUtils.fromBase58(serialized);
        return parseBytesWIF(store);
    }

    public ECKeyPair parseBytesWIF(byte[] store) throws ValidationException {
        if (store.length == 37) {
            checkChecksum(store);
            byte[] key = new byte[store.length - 5];
            System.arraycopy(store, 1, key, 0, store.length - 5);
            return new ECKeyPair(key, false);
        } else if (store.length == 38) {
            checkChecksum(store);
            byte[] key = new byte[store.length - 6];
            System.arraycopy(store, 1, key, 0, store.length - 6);
            return new ECKeyPair(key, true);
        }
        throw new ValidationException("Invalid key length");
    }

    private void checkChecksum(byte[] store) throws ValidationException {
        byte[] checksum = new byte[4];
        System.arraycopy(store, store.length - 4, checksum, 0, 4);
        byte[] ekey = new byte[store.length - 4];
        System.arraycopy(store, 0, ekey, 0, store.length - 4);
        byte[] hash = ByteUtils.hash(ekey);
        for (int i = 0; i < 4; ++i) {
            if (hash[i] != checksum[i]) {
                throw new ValidationException("checksum mismatch");
            }
        }
    }

}

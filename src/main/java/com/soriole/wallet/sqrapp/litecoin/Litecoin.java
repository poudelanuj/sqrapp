package com.soriole.wallet.sqrapp.litecoin;

import com.soriole.wallet.sqrapp.CryptoCurrency;

public class Litecoin implements CryptoCurrency{
    @Override
    public byte[] newSeed() {
        return new byte[0];
    }

    @Override
    public byte[] newPrivateKey() {
        return new byte[0];
    }

    @Override
    public byte[] newPrivateKey(byte[] seed) {
        return new byte[0];
    }

    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {
        return new byte[0];
    }

    @Override
    public byte[] publicKey(byte[] privateKey) {
        return new byte[0];
    }
}

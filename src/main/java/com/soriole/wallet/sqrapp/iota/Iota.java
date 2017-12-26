package com.soriole.wallet.sqrapp.iota;

import com.soriole.wallet.sqrapp.CryptoCurrency;

public class Iota implements CryptoCurrency{
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

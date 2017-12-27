/*
 * Copyright 2013 bits of proof zrt.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Adapted from https://github.com/bitsofproof/supernode/blob/1.1/api/src/main/java/com/bitsofproof/supernode/api/ExtendedKey.java
 */

package com.soriole.wallet.sqrapp.bitcoin;

import com.soriole.wallet.lib.ByteUtils;
import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.lib.exceptions.ValidationException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;

public class BitcoinExtendedKey {
    private static final SecureRandom rnd = new SecureRandom();
    private static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");

    private static final byte[] xprv = new byte[]{0x04, (byte) 0x88, (byte) 0xAD, (byte) 0xE4};
    private static final byte[] xpub = new byte[]{0x04, (byte) 0x88, (byte) 0xB2, (byte) 0x1E};
    private static final byte[] tprv = new byte[]{0x04, (byte) 0x35, (byte) 0x83, (byte) 0x94};
    private static final byte[] tpub = new byte[]{0x04, (byte) 0x35, (byte) 0x87, (byte) 0xCF};

    private final ECKeyPair master;
    private final byte[] chainCode;
    private final int depth;
    private final int parent;
    private final int sequence;

    private static final byte[] BITCOIN_SEED = "Bitcoin seed".getBytes();

    public BitcoinExtendedKey(ECKeyPair key, byte[] chainCode, int depth, int parent, int sequence) {
        this.master = key;
        this.chainCode = chainCode;
        this.parent = parent;
        this.depth = depth;
        this.sequence = sequence;
    }

    public ECKeyPair getMaster() {
        return master;
    }

    public byte[] getChainCode() {
        return Arrays.clone(chainCode);
    }

    public int getDepth() {
        return depth;
    }

    public int getParent() {
        return parent;
    }

    public int getSequence() {
        return sequence;
    }

    public int getFingerPrint() {
        int fingerprint = 0;
        byte[] address = master.getAddress();
        for (int i = 0; i < 4; ++i) {
            fingerprint <<= 8;
            fingerprint |= address[i] & 0xff;
        }
        return fingerprint;
    }

    public ECKeyPair getKey(int sequence) throws ValidationException {
        return generateKey(sequence).getMaster();
    }

    public BitcoinExtendedKey getChild(int sequence) throws ValidationException {
        BitcoinExtendedKey sub = generateKey(sequence);
        return new BitcoinExtendedKey(sub.getMaster(), sub.getChainCode(), sub.getDepth() + 1, getFingerPrint(), sequence);
    }

    public BitcoinExtendedKey getReadOnly() {
        ECKeyPair keyPair = ECKeyPair.publicOnly(master.getPublic(), true);
        return new BitcoinExtendedKey(keyPair, chainCode, depth, parent, sequence);
    }

    public boolean isReadOnly() {
        return master.getPrivate() == null;
    }

    private BitcoinExtendedKey generateKey(int sequence) throws ValidationException {
        try {
            if ((sequence & 0x80000000) != 0 && master.getPrivate() == null) {
                throw new ValidationException("need private key for private generation");
            }
            Mac mac = Mac.getInstance("HmacSHA512", "BC");
            SecretKey key = new SecretKeySpec(chainCode, "HmacSHA512");
            mac.init(key);

            byte[] extended;
            byte[] pub = master.getPublic();
            if ((sequence & 0x80000000) == 0) {
                extended = new byte[pub.length + 4];
                System.arraycopy(pub, 0, extended, 0, pub.length);
                extended[pub.length] = (byte) ((sequence >>> 24) & 0xff);
                extended[pub.length + 1] = (byte) ((sequence >>> 16) & 0xff);
                extended[pub.length + 2] = (byte) ((sequence >>> 8) & 0xff);
                extended[pub.length + 3] = (byte) (sequence & 0xff);
            } else {
                byte[] priv = master.getPrivate();
                extended = new byte[priv.length + 5];
                System.arraycopy(priv, 0, extended, 1, priv.length);
                extended[priv.length + 1] = (byte) ((sequence >>> 24) & 0xff);
                extended[priv.length + 2] = (byte) ((sequence >>> 16) & 0xff);
                extended[priv.length + 3] = (byte) ((sequence >>> 8) & 0xff);
                extended[priv.length + 4] = (byte) (sequence & 0xff);
            }
            byte[] lr = mac.doFinal(extended);
            byte[] l = Arrays.copyOfRange(lr, 0, 32);
            byte[] r = Arrays.copyOfRange(lr, 32, 64);

            BigInteger m = new BigInteger(1, l);
            if (m.compareTo(curve.getN()) >= 0) {
                throw new ValidationException("This is rather unlikely, but it did just happen");
            }
            if (master.getPrivate() != null) {
                BigInteger k = m.add(new BigInteger(1, master.getPrivate())).mod(curve.getN());
                if (k.equals(BigInteger.ZERO)) {
                    throw new ValidationException("This is rather unlikely, but it did just happen");
                }
                return new BitcoinExtendedKey(new ECKeyPair(k, true), r, depth, parent, sequence);
            } else {
                ECPoint q = curve.getG().multiply(m).add(curve.getCurve().decodePoint(pub));
                if (q.isInfinity()) {
                    throw new ValidationException("This is rather unlikely, but it did just happen");
                }
                pub = q.getEncoded(true);//new ECPoint.Fp(curve.getCurve(), q.getX(), q.getY(), true).getEncoded();
                return new BitcoinExtendedKey(ECKeyPair.publicOnly(pub, true), r, depth, parent, sequence);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new ValidationException(e);
        } catch (NoSuchProviderException e) {
            throw new ValidationException(e);
        } catch (InvalidKeyException e) {
            throw new ValidationException(e);
        }
    }

    public static BitcoinExtendedKey createNew() {
        ECKeyPair key = ECKeyPair.createNew(true);
        byte[] chainCode = new byte[32];
        rnd.nextBytes(chainCode);
        return new BitcoinExtendedKey(key, chainCode, 0, 0, 0);
    }

    public static BitcoinExtendedKey create(byte[] seed) throws ValidationException {
        try {
            Mac mac = Mac.getInstance("HmacSHA512", "BC");
            SecretKey seedkey = new SecretKeySpec(BITCOIN_SEED, "HmacSHA512");
            mac.init(seedkey);
            byte[] lr = mac.doFinal(seed);
            byte[] l = Arrays.copyOfRange(lr, 0, 32);
            byte[] r = Arrays.copyOfRange(lr, 32, 64);
            BigInteger m = new BigInteger(1, l);
            if (m.compareTo(curve.getN()) >= 0) {
                throw new ValidationException("This is rather unlikely, but it did just happen");
            }
            ECKeyPair keyPair = new ECKeyPair(l, true);
            return new BitcoinExtendedKey(keyPair, r, 0, 0, 0);
        } catch (NoSuchAlgorithmException e) {
            throw new ValidationException(e);
        } catch (NoSuchProviderException e) {
            throw new ValidationException(e);
        } catch (InvalidKeyException e) {
            throw new ValidationException(e);
        }
    }

    public static BitcoinExtendedKey parse(String serialized) throws ValidationException {
        byte[] data = ByteUtils.fromBase58WithChecksum(serialized);
        if (data.length != 78) {
            throw new ValidationException("invalid extended key");
        }
        byte[] type = Arrays.copyOf(data, 4);
        boolean hasPrivate;
        if (Arrays.areEqual(type, xprv) || Arrays.areEqual(type, tprv)) {
            hasPrivate = true;
        } else if (Arrays.areEqual(type, xpub) || Arrays.areEqual(type, tpub)) {
            hasPrivate = false;
        } else {
            throw new ValidationException("invalid magic number for an extended key");
        }

        int depth = data[4] & 0xff;

        int parent = data[5] & 0xff;
        parent <<= 8;
        parent |= data[6] & 0xff;
        parent <<= 8;
        parent |= data[7] & 0xff;
        parent <<= 8;
        parent |= data[8] & 0xff;

        int sequence = data[9] & 0xff;
        sequence <<= 8;
        sequence |= data[10] & 0xff;
        sequence <<= 8;
        sequence |= data[11] & 0xff;
        sequence <<= 8;
        sequence |= data[12] & 0xff;

        byte[] chainCode = Arrays.copyOfRange(data, 13, 13 + 32);
        byte[] pubOrPriv = Arrays.copyOfRange(data, 13 + 32, data.length);
        ECKeyPair key;
        if (hasPrivate) {
            key = new ECKeyPair(new BigInteger(1, pubOrPriv), true);
        } else {
            key = new ECKeyPair(pubOrPriv, true);
        }
        return new BitcoinExtendedKey(key, chainCode, depth, parent, sequence);
    }

    public String serialize(boolean production) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            if (master.getPrivateKey() != null) {
                if (production) {
                    out.write(xprv);
                } else {
                    out.write(tprv);
                }
            } else {
                if (production) {
                    out.write(xpub);
                } else {
                    out.write(tpub);
                }
            }
            out.write(depth & 0xff);
            out.write((parent >>> 24) & 0xff);
            out.write((parent >>> 16) & 0xff);
            out.write((parent >>> 8) & 0xff);
            out.write(parent & 0xff);
            out.write((sequence >>> 24) & 0xff);
            out.write((sequence >>> 16) & 0xff);
            out.write((sequence >>> 8) & 0xff);
            out.write(sequence & 0xff);
            out.write(chainCode);
            if (master.getPrivateKey() != null) {
                out.write(0x00);
                out.write(master.getPrivate());
            } else {
                out.write(master.getPublic());
            }
        } catch (IOException e) {
        }
        return ByteUtils.toBase58WithChecksum(out.toByteArray());
    }

    public static BitcoinExtendedKey createFromPassphrase(String passphrase, byte[] encrypted) throws ValidationException {
        try {
            byte[] key = SCrypt.generate(passphrase.getBytes("UTF-8"), BITCOIN_SEED, 16384, 8, 8, 32);
            SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
            if (encrypted.length == 32) {
                // asssume encrypted is seed
                Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
                cipher.init(Cipher.DECRYPT_MODE, keyspec);
                return create(cipher.doFinal(encrypted));
            } else {
                // assume encrypted serialization of a key
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
                byte[] iv = Arrays.copyOfRange(encrypted, 0, 16);
                byte[] data = Arrays.copyOfRange(encrypted, 16, encrypted.length);
                cipher.init(Cipher.DECRYPT_MODE, keyspec, new IvParameterSpec(iv));
                return BitcoinExtendedKey.parse(new String(cipher.doFinal(data)));
            }
        } catch (UnsupportedEncodingException e) {
            throw new ValidationException(e);
        } catch (IllegalBlockSizeException e) {
            throw new ValidationException(e);
        } catch (BadPaddingException e) {
            throw new ValidationException(e);
        } catch (InvalidKeyException e) {
            throw new ValidationException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new ValidationException(e);
        } catch (NoSuchProviderException e) {
            throw new ValidationException(e);
        } catch (NoSuchPaddingException e) {
            throw new ValidationException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new ValidationException(e);
        }
    }

    public byte[] encrypt(String passphrase, boolean production) throws ValidationException {
        try {
            byte[] key = SCrypt.generate(passphrase.getBytes("UTF-8"), BITCOIN_SEED, 16384, 8, 8, 32);
            SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, keyspec);
            byte[] iv = cipher.getIV();
            byte[] c = cipher.doFinal(serialize(production).getBytes());
            byte[] result = new byte[iv.length + c.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(c, 0, result, iv.length, c.length);
            return result;
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new ValidationException(e);
        }
    }

}

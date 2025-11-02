package aes;

import java.util.Arrays;

/** Modos de operação: ECB, CBC (PKCS#7) e CTR (sem padding). */
public class Modes {

    // ===== ECB =====
    public static byte[] encryptECB(AES aes, byte[] plain) {
        byte[] p = PKCS7.addPadding(plain, 16);
        byte[] out = new byte[p.length];
        for (int i = 0; i < p.length; i += 16) {
            byte[] block = Arrays.copyOfRange(p, i, i + 16);
            byte[] c = aes.encryptBlock(block);
            System.arraycopy(c, 0, out, i, 16);
        }
        return out;
    }

    public static byte[] decryptECB(AES aes, byte[] cipher) {
        if (cipher.length % 16 != 0) throw new IllegalArgumentException("Tamanho inválido para ECB");
        byte[] out = new byte[cipher.length];
        for (int i = 0; i < cipher.length; i += 16) {
            byte[] block = Arrays.copyOfRange(cipher, i, i + 16);
            byte[] p = aes.decryptBlock(block);
            System.arraycopy(p, 0, out, i, 16);
        }
        return PKCS7.removePadding(out, 16);
    }

    // ===== CBC =====
    public static byte[] encryptCBC(AES aes, byte[] plain, byte[] iv) {
        if (iv == null || iv.length != 16) throw new IllegalArgumentException("IV deve ter 16 bytes");
        byte[] p = PKCS7.addPadding(plain, 16);
        byte[] out = new byte[p.length];
        byte[] prev = Arrays.copyOf(iv, 16);

        for (int i = 0; i < p.length; i += 16) {
            byte[] block = Arrays.copyOfRange(p, i, i + 16);
            for (int j = 0; j < 16; j++) block[j] ^= prev[j];
            byte[] c = aes.encryptBlock(block);
            System.arraycopy(c, 0, out, i, 16);
            prev = c;
        }
        return out;
    }

    public static byte[] decryptCBC(AES aes, byte[] cipher, byte[] iv) {
        if (iv == null || iv.length != 16) throw new IllegalArgumentException("IV deve ter 16 bytes");
        if (cipher.length % 16 != 0) throw new IllegalArgumentException("Tamanho inválido para CBC");
        byte[] out = new byte[cipher.length];
        byte[] prev = Arrays.copyOf(iv, 16);

        for (int i = 0; i < cipher.length; i += 16) {
            byte[] block = Arrays.copyOfRange(cipher, i, i + 16);
            byte[] p = aes.decryptBlock(block);
            for (int j = 0; j < 16; j++) p[j] ^= prev[j];
            System.arraycopy(p, 0, out, i, 16);
            prev = block;
        }
        return PKCS7.removePadding(out, 16);
    }

    // ===== CTR (enc = dec) =====
    public static byte[] applyCTR(AES aes, byte[] data, byte[] nonceCounter16) {
        if (nonceCounter16 == null || nonceCounter16.length != 16)
            throw new IllegalArgumentException("nonce+counter deve ter 16 bytes");
        byte[] out = new byte[data.length];
        byte[] counter = Arrays.copyOf(nonceCounter16, 16);

        for (int i = 0; i < data.length; i += 16) {
            byte[] keystream = aes.encryptBlock(counter);
            int blockSize = Math.min(16, data.length - i);
            for (int j = 0; j < blockSize; j++) {
                out[i + j] = (byte)(data[i + j] ^ keystream[j]);
            }
            incrementCounter(counter);
        }
        return out;
    }

    private static void incrementCounter(byte[] counter) {
        for (int i = 15; i >= 0; i--) {
            counter[i]++;
            if ((counter[i] & 0xff) != 0) break;
        }
    }
}

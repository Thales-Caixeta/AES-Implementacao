package aes;

import java.util.Arrays;

/** Padding PKCS#7 padrão para blocos de 16 bytes. */
public class PKCS7 {
    public static byte[] addPadding(byte[] data, int blockSize) {
        int pad = blockSize - (data.length % blockSize);
        if (pad == 0) pad = blockSize;
        byte[] out = Arrays.copyOf(data, data.length + pad);
        for (int i = data.length; i < out.length; i++) out[i] = (byte) pad;
        return out;
    }

    public static byte[] removePadding(byte[] data, int blockSize) {
        if (data.length == 0 || data.length % blockSize != 0)
            throw new IllegalArgumentException("Dados inválidos para PKCS#7");
        int pad = data[data.length - 1] & 0xff;
        if (pad < 1 || pad > blockSize) throw new IllegalArgumentException("Padding inválido");
        for (int i = 1; i <= pad; i++) {
            if ((data[data.length - i] & 0xff) != pad) throw new IllegalArgumentException("Padding inválido");
        }
        return Arrays.copyOf(data, data.length - pad);
    }
}

package aes;

/** Utilitários simples para Hex ⇄ bytes. */
public class Hex {
    public static byte[] fromHex(String s) {
        s = s.replaceAll("\\s+", "");
        if (s.length() % 2 != 0) throw new IllegalArgumentException("Hex inválido");
        byte[] out = new byte[s.length()/2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2*i), 16);
            int lo = Character.digit(s.charAt(2*i+1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Hex inválido");
            out[i] = (byte)((hi << 4) | lo);
        }
        return out;
    }

    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length*2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}

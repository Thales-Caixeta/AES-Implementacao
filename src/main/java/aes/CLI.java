package aes;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * CLI simples para usar o AES.
 *
 * Uso:
 *   # ECB
 *   java -cp src/main/java aes.CLI enc ecb <hexKey> <inFile> <outFile>
 *   java -cp src/main/java aes.CLI dec ecb <hexKey> <inFile> <outFile>
 *
 *   # CBC (IV em hex, 16 bytes)
 *   java -cp src/main/java aes.CLI enc cbc <hexKey> <hexIV> <inFile> <outFile>
 *   java -cp src/main/java aes.CLI dec cbc <hexKey> <hexIV> <inFile> <outFile>
 *
 *   # CTR (nonce+counter 16 bytes em hex) — enc/dec iguais
 *   java -cp src/main/java aes.CLI ctr <hexKey> <hexNonceCounter> <inFile> <outFile>
 *
 *   # Self-test com vetor NIST
 *   java -cp src/main/java aes.CLI selftest
 */
public class CLI {

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equalsIgnoreCase("selftest")) {
            selfTest();
            return;
        }

        if (args.length < 5) {
            System.out.println("Uso:");
            System.out.println("  java aes.CLI enc ecb <hexKey> <inFile> <outFile>");
            System.out.println("  java aes.CLI dec ecb <hexKey> <inFile> <outFile>");
            System.out.println("  java aes.CLI enc cbc <hexKey> <hexIV> <inFile> <outFile>");
            System.out.println("  java aes.CLI dec cbc <hexKey> <hexIV> <inFile> <outFile>");
            System.out.println("  java aes.CLI ctr <hexKey> <hexNonceCounter> <inFile> <outFile>");
            System.out.println("  java aes.CLI selftest");
            return;
        }

        String op = args[0].toLowerCase();
        String mode = args[1].toLowerCase();

        if (mode.equals("ecb")) {
            String hexKey = args[2];
            String inFile = args[3];
            String outFile = args[4];

            byte[] key = Hex.fromHex(hexKey);
            AES aes = new AES(key);
            byte[] input = Files.readAllBytes(Paths.get(inFile));
            if (op.equals("enc")) {
                byte[] out = Modes.encryptECB(aes, input);
                Files.write(Paths.get(outFile), out);
            } else if (op.equals("dec")) {
                byte[] out = Modes.decryptECB(aes, input);
                Files.write(Paths.get(outFile), out);
            } else throw new IllegalArgumentException("Operação inválida");
            return;
        }

        if (mode.equals("cbc")) {
            if (args.length < 6) throw new IllegalArgumentException("Faltou IV em hex");
            String hexKey = args[2];
            String hexIV  = args[3];
            String inFile = args[4];
            String outFile = args[5];

            byte[] key = Hex.fromHex(hexKey);
            byte[] iv  = Hex.fromHex(hexIV);
            AES aes = new AES(key);
            byte[] input = Files.readAllBytes(Paths.get(inFile));
            if (op.equals("enc")) {
                byte[] out = Modes.encryptCBC(aes, input, iv);
                Files.write(Paths.get(outFile), out);
            } else if (op.equals("dec")) {
                byte[] out = Modes.decryptCBC(aes, input, iv);
                Files.write(Paths.get(outFile), out);
            } else throw new IllegalArgumentException("Operação inválida");
            return;
        }

        if (mode.equals("ctr")) {
            if (args.length < 6) throw new IllegalArgumentException("Faltou nonce+counter (16 bytes hex)");
            String hexKey = args[2];
            String hexNC  = args[3];
            String inFile = args[4];
            String outFile = args[5];

            byte[] key = Hex.fromHex(hexKey);
            byte[] nc  = Hex.fromHex(hexNC);
            AES aes = new AES(key);
            byte[] input = Files.readAllBytes(Paths.get(inFile));
            byte[] out = Modes.applyCTR(aes, input, nc); // mesmo para enc/dec
            Files.write(Paths.get(outFile), out);
            return;
        }

        throw new IllegalArgumentException("Modo inválido");
    }

    // Vetor canônico do NIST (AES-128)
    private static void selfTest() {
        byte[] key = Hex.fromHex("000102030405060708090a0b0c0d0e0f");
        byte[] plain = Hex.fromHex("00112233445566778899aabbccddeeff");
        byte[] expected = Hex.fromHex("69c4e0d86a7b0430d8cdb78070b4c55a");

        AES aes = new AES(key);
        byte[] got = aes.encryptBlock(plain);

        System.out.println("AES-128 rounds: " + aes.getNr());
        System.out.println("cipher:   " + Hex.toHex(got));
        System.out.println("expected: " + Hex.toHex(expected));
        System.out.println("ok: " + Arrays.equals(got, expected));
    }
}

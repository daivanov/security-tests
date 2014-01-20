import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.util.encoders.Hex;

public class Agreement {

    private static SRP6Client client = new SRP6Client();

    private static SRP6Server server = new SRP6Server();

    private static SHA224Digest digest = new SHA224Digest();

    private static SecureRandom random = new SecureRandom();

    // Values from RFC5054
    private static final BigInteger N = new BigInteger(1,
        Hex.decode(
            "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
            "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
            "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
            "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
            "FD5138FE8376435B9FC61D2FC0EB06E3"));

    private static final BigInteger g = BigInteger.valueOf(2);

    public static BigInteger getVerifier(byte[] salt, byte[] identity,
            byte[] password) {

        SRP6VerifierGenerator gen = new SRP6VerifierGenerator();
        gen.init(N, g, digest);
        return gen.generateVerifier(salt, identity, password);
    }

    public static BigInteger getClientCredentials(byte[] salt, byte[] identity,
            byte[] password) {

        client.init(N, g, digest, random);
        return client.generateClientCredentials(salt, identity, password);
    }

    public static BigInteger getServerCredentials(BigInteger verifier) {

        server.init(N, g, verifier, digest, random);
        return server.generateServerCredentials();
    }

    public static void test() {
        byte[] identity = "username".getBytes();
        byte[] password = "password".getBytes();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        BigInteger clientCreds = getClientCredentials(salt, identity, password);
        System.out.println("Client credentials:\n" + clientCreds.toString(16));

        BigInteger verifier = getVerifier(salt, identity, password);
        BigInteger serverCreds = getServerCredentials(verifier);
        System.out.println("Server credentials:\n" + serverCreds.toString(16));

        try {
            BigInteger clientS = client.calculateSecret(serverCreds);
            System.out.println("Client secret:\n" + clientS.toString(16));

            BigInteger serverS = server.calculateSecret(clientCreds);
            System.out.println("Server secret:\n" + serverS.toString(16));
            if (clientS.equals(serverS)) {
                System.out.println("Agreement succeed");
            }
        } catch(CryptoException e) {
            System.out.println(e.toString());
        }
    }
}

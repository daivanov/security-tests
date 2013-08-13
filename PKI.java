import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECGOST3410Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
//import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.util.encoders.Hex;

public class PKI {

    public static KeyPairGenerator getKeyPairGenerator(String algorithm, String parameter) {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            AlgorithmParameterSpec spec = new ECGenParameterSpec(parameter);
            keyPairGenerator.initialize(spec, new SecureRandom());
        } catch(GeneralSecurityException e) {
            System.out.println(e.toString());
        }
        return keyPairGenerator;
    }

    public static KeyPair generateKeyPair(KeyPairGenerator keyPairGenerator) {
        KeyPair keyPair = null;
        if (keyPairGenerator != null) {
            keyPair = keyPairGenerator.generateKeyPair();
        }
        return keyPair;
    }

    public static X509Certificate generateSelfSignedCertificate(
        PublicKey publicKey, KeyPair issuerKeyPair,
        X509Name subjectDN, X509Name issuerDN, X509Extensions extensions,
        String signingAlgorithm)
        throws GeneralSecurityException, CertificateParsingException {

        long timestamp = System.currentTimeMillis();
        Date startDate = new Date(timestamp);
        Date expiryDate = new Date(timestamp + 31536000000L);

        byte[] serial = longToBytes(timestamp);
        BigInteger serialNumber = new BigInteger(serial);

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(serialNumber);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setIssuerDN(issuerDN);
        certGen.setSubjectDN(subjectDN);
        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm(signingAlgorithm);

        if (extensions != null) {
            Enumeration<DERObjectIdentifier> oids = extensions.oids();
            while (oids.hasMoreElements()) {
                DERObjectIdentifier oid = oids.nextElement();
                X509Extension extension = extensions.getExtension(oid);
                ASN1Object value;
                if (X509Extensions.SubjectKeyIdentifier.equals(oid)) {
                    value = new SubjectKeyIdentifierStructure(publicKey);
                } else if (X509Extensions.AuthorityKeyIdentifier.equals(oid)) {
                    value = new AuthorityKeyIdentifierStructure(issuerKeyPair.getPublic());
                } else {
                    value = extension.getValue();
                }
                certGen.addExtension(oid, extension.isCritical(), value);
            }
        }

        X509Certificate cert = certGen.generate(issuerKeyPair.getPrivate(),
                BouncyCastleProvider.PROVIDER_NAME);
        return cert;
    }

    public static ECParameterSpec generateParameterSpec(String algorithm, String parameter) {
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator(algorithm, parameter);
        KeyPair keyPair = generateKeyPair(keyPairGenerator);
        ECParameterSpec paramSpec = null;
        if (keyPair != null) {
            PublicKey publicKey = keyPair.getPublic();
            if (publicKey instanceof ECKey) {
                ECKey ecKey = (ECKey)publicKey;
                paramSpec = ecKey.getParams();
            }
        }
        return paramSpec;
    }

    public static PublicKey recoverECPublicKey(String algorithm, ECPoint point, ECParameterSpec paramSpec) {
        PublicKey publicKey = null;
        if (point != null && paramSpec != null) {
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, paramSpec);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
                publicKey = keyFactory.generatePublic(pubKeySpec);
                System.out.println(publicKey.toString());
            } catch(GeneralSecurityException e) {
                System.out.println(e.toString());
            }
        }
        return publicKey;
    }

    public static PrivateKey recoverECPrivateKey(String algorithm, BigInteger point, ECParameterSpec paramSpec) {
        PrivateKey privateKey = null;
        if (point != null && paramSpec != null) {
            ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(point, paramSpec);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
                privateKey = keyFactory.generatePrivate(privKeySpec);
                System.out.println(privateKey.toString());
            } catch(GeneralSecurityException e) {
                System.out.println(e.toString());
            }
        }
        return privateKey;
    }

    public static byte[] sign(String algorithm, PrivateKey privateKey, byte[] messageBytes) {
        byte[] signatureBytes = null;
        try {
            Signature signature = Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            signature.initSign(privateKey);
            signature.update(messageBytes);
            signatureBytes = signature.sign();
        } catch(GeneralSecurityException e) {
            System.out.println(e.toString());
        }
        return signatureBytes;
    }

    public static byte[] signHashECGOST3410(byte[] hash, PrivateKey privateKey) {
        byte[] signature = null;
        ECGOST3410Signer gost3410Signer = new ECGOST3410Signer();
        try {
            CipherParameters param = ECUtil.generatePrivateKeyParameter(privateKey);
            gost3410Signer.init(true, param);
            BigInteger[] sigBigInts = gost3410Signer.generateSignature(hash);
            byte[] r = sigBigInts[0].toByteArray();
            byte[] s = sigBigInts[1].toByteArray();

            signature = new byte[64];

            int sOffset = (s[0] == 0) ? 1 : 0;
            System.arraycopy(s, sOffset, signature, 32 - (s.length - sOffset), s.length - sOffset);

            int rOffset = (r[0] == 0) ? 1 : 0;
            System.arraycopy(r, rOffset, signature, 64 - (r.length - rOffset), r.length - rOffset);
        } catch(GeneralSecurityException e) {
            System.out.println(e.toString());
        }
        return signature;
    }

    public static boolean verify(String algorithm, PublicKey publicKey, byte[] messageBytes, byte[] signatureBytes) {
        boolean valid = false;
        try {
            Signature signature = Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            signature.initVerify(publicKey);
            signature.update(messageBytes);
            valid = signature.verify(signatureBytes);
        } catch(GeneralSecurityException e) {
            System.out.println(e.toString());
        }
        return valid;
    }

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());
        System.out.println(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME).getInfo());

        KeyPairGenerator keyPairGenerator = getKeyPairGenerator("ECGOST3410", "GostR3410-2001-CryptoPro-A");

        KeyPair keyPair = generateKeyPair(keyPairGenerator);

        if (keyPair != null) {
            X509Name subjectDN = new X509Name("CN=test");
            try {
                X509Certificate certificate = generateSelfSignedCertificate(
                    keyPair.getPublic(), keyPair, subjectDN, subjectDN, null,
                    "GOST3411withECGOST3410");
                byte[] certificateEnc = certificate.getEncoded();
                printDEREncoded("Self-signed certificate", certificateEnc);
            } catch (Exception e) {
                System.out.println(e.toString());
            }
        }

        ECPoint point = null;
        BigInteger point2 = null;
        ECParameterSpec paramSpec = null;
        if (keyPair != null) {
            PublicKey publicKey = keyPair.getPublic();
            System.out.println(publicKey.toString());
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println(privateKey.toString());
            if (privateKey instanceof ECPrivateKey) {
                ECPrivateKey ecPrivateKey = (ECPrivateKey)privateKey;
                point2 = ecPrivateKey.getS();
            }
            if (publicKey instanceof ECPublicKey) {
                ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
                point = ecPublicKey.getW();
                BigInteger affineX = point.getAffineX();
                System.out.println("X\t" + affineX.toString(16));
                BigInteger affineY = point.getAffineY();
                System.out.println("Y\t" + affineY.toString(16));
                paramSpec = ecPublicKey.getParams();
                System.out.println("Co-factor\t" + paramSpec.getCofactor());
                System.out.println("Curve A\t" + paramSpec.getCurve().getA().toString(16));
                System.out.println("Curve B\t" + paramSpec.getCurve().getB().toString(16));
                System.out.println("Curve filed size\t" + paramSpec.getCurve().getField().getFieldSize());
                System.out.println("Generator X\t" + paramSpec.getGenerator().getAffineX().toString(16));
                System.out.println("Generator Y\t" + paramSpec.getGenerator().getAffineY().toString(16));
                System.out.println("Order\t" + paramSpec.getOrder().toString(16));
            }
        }

        PublicKey recoveredPubKey = recoverECPublicKey("ECGOST3410", point,
            generateParameterSpec("ECGOST3410", "GostR3410-2001-CryptoPro-A"));

        PrivateKey recoveredPrivKey = recoverECPrivateKey("ECGOST3410", point2,
            generateParameterSpec("ECGOST3410", "GostR3410-2001-CryptoPro-A"));

        /* Encrypt/Decrypt */
        byte[] message = Hex.decode("1234567890abcdef");
        System.out.println("Message\t" + toHexStr(message));

        if (keyPair != null) {
            byte[] derivation = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] encoding = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
            IESParameterSpec iesSpec = new IESParameterSpec(derivation, encoding, 128);
            Key publicKey = keyPair.getPublic();
            //Key publicKey = new IEKeySpec(keyPair.getPrivate(), keyPair.getPublic());
            Key privateKey = keyPair.getPrivate();
            //Key privateKey = new IEKeySpec(keyPair.getPrivate(), keyPair.getPublic());
            try {

                Cipher cipher1 = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
                cipher1.init(Cipher.ENCRYPT_MODE, publicKey, iesSpec);
                byte[] encrypted = cipher1.doFinal(message, 0, message.length);

                System.out.println("Encrypted\t" + toHexStr(encrypted));

                Cipher cipher2 = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
                cipher2.init(Cipher.DECRYPT_MODE, privateKey, iesSpec);
                byte[] decrypted = cipher2.doFinal(encrypted, 0, encrypted.length);

                System.out.println("Decrypted\t" + toHexStr(decrypted));
            } catch(GeneralSecurityException e) {
                System.out.println(e.toString());
            }
        }

        byte[] signatureBytes = sign("GOST3411withECGOST3410", keyPair.getPrivate(), message);
        System.out.println("Signature\n" + toHexStr(signatureBytes).replaceAll("(.{64})", "$1\n"));

        /* Compute digest */
        byte[] hash = null;
        try {
            MessageDigest md = MessageDigest.getInstance("GOST3411", BouncyCastleProvider.PROVIDER_NAME);
            hash = md.digest(message);
            System.out.println("Hash\n" + toHexStr(hash));
        } catch(GeneralSecurityException e) {
            System.out.println(e.toString());
        }

        /* Sign digest */
        byte[] hashSignatureBytes = signHashECGOST3410(hash, keyPair.getPrivate());
        System.out.println("Hash signature\n" + toHexStr(hashSignatureBytes).replaceAll("(.{64})", "$1\n"));

        if (verify("GOST3411withECGOST3410", keyPair.getPublic(), message, signatureBytes)) {
            System.out.println("Signature\tvalid");
        } else {
            System.out.println("Signature\tinvalid");
        }

        if (verify("GOST3411withECGOST3410", recoveredPubKey, message, signatureBytes)) {
            System.out.println("Signature with recovered key\tvalid");
        } else {
            System.out.println("Signature with recovered key\tinvalid");
        }

        if (verify("GOST3411withECGOST3410", keyPair.getPublic(), message, hashSignatureBytes)) {
            System.out.println("Hash signature\tvalid");
        } else {
            System.out.println("Hash signature\tinvalid");
        }

        /* Encode signature as ASN.1 DER */
        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
        AlgorithmIdentifier algoId = finder.find("GOST3411withECGOST3410");
        printDEREncoded(algoId.getAlgorithm().toString(), algoId);
        org.bouncycastle.asn1.ocsp.Signature asn1signature = new org.bouncycastle.asn1.ocsp.Signature(
            algoId, new DERBitString(hashSignatureBytes));
        printDEREncoded("Signature", asn1signature);
    }

    private static byte[] longToBytes(long value) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(value);
        return buffer.array();
    }

    private static ASN1Object bytesToDER(byte[] asn1data) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(asn1data);
        ASN1InputStream ais = new ASN1InputStream(bais);
        ASN1Object obj = ais.readObject();
        return obj;
    }

    private static void printDEREncoded(String message, byte[] asn1encoded) {
        try {
            ASN1Object object = bytesToDER(asn1encoded);
            printDEREncoded(message, object);
        } catch(IOException e) {
            System.out.println(message + "\t" + e.toString());
        }
    }

    private static void printDEREncoded(String message, ASN1Object object) {
        try {
            byte[] derEncoded = object.getEncoded("DER");
            System.out.println(message +
                "\n" + toHexStr(derEncoded) +
                "\n" + ASN1Dump.dumpAsString(object, true));
        } catch(IOException e) {
            System.out.println(message + "\t" + e.toString());
        }
    }

    private static String toHexStr(byte[] bytes) {
        return new BigInteger(1, bytes).toString(16);
    }
}

package eu.cybertrust.cryptoutils;

import org.bouncycastle.util.encoders.Base64;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Loader {

	private static String getKey(String filename) throws IOException {
	    // Read key from file
	    String strKeyPEM = "";
	    BufferedReader br = new BufferedReader(new FileReader(filename));
	    String line;
	    while ((line = br.readLine()) != null) {
	        strKeyPEM += line + "\n";
	    }
	    br.close();
	    return strKeyPEM;
	}
	public static RSAPrivateKey getPrivateKeyFromFile(String filename) throws IOException, GeneralSecurityException {
	    String privateKeyPEM = getKey(filename);
	    return getPrivateKeyFromString(privateKeyPEM);
	}

	public static RSAPrivateKey getPrivateKeyFromString(String key) throws GeneralSecurityException {
	    String privateKeyPEM = key;
	    privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
	    privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
	    byte[] encoded = Base64.decode(privateKeyPEM);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
	    RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
	    return privKey;
	}

	public static RSAPublicKey getPublicKeyFromFile(String filename) throws IOException, GeneralSecurityException {
	    String publicKeyPEM = getKey(filename);
	    return getPublicKeyFromString(publicKeyPEM);
	}

	public static RSAPublicKey getPublicKeyFromString(String key) throws IOException, GeneralSecurityException {
	    String publicKeyPEM = key;
	    publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
	    publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
	    byte[] encoded = Base64.decode(publicKeyPEM);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
	    return pubKey;
	}

	public static RSAPublicKey getPublicKeyFromCertificateFile(String filename) throws IOException, GeneralSecurityException {
		FileInputStream fin = new FileInputStream(filename);
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
		return (RSAPublicKey) (certificate.getPublicKey());
	}

}

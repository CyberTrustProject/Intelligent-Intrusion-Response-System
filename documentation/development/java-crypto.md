```java
try {
    // Load the private key.
    File file = new File(System.getProperty("user.home") + "/.remediation/crypto-keys/public_key.pem");
    PemReader PEMreader = new PemReader(new FileReader(file));
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(PEMreader.readPemObject().getContent());
    RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);

    // Initialize the signing object.
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initSign(privateKey);

    // Sign something
    String test = "This is a test";
    sig.update(test.getBytes());
    String tehidgiue = new String(Base64.encode(sig.sign()));

    // ---------------------------------------------------------------------------------------------------------
    // Load the certificate.
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    FileInputStream fileIN = new FileInputStream(System.getProperty("user.home") + "/.remediation/crypto-keys/certificate.pem");
    X509Certificate cert = (X509Certificate) cf.generateCertificate(fileIN);
    Signature sign = Signature.getInstance("SHA256withRSA");
    sign.initVerify(cert.getPublicKey());
    sign.update(test.getBytes());

    System.out.println(sign.verify(Base64.decode(tehidgiue)));
} catch (Exception e) {
    e.printStackTrace();
}
```

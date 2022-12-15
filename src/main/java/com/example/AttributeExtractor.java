package com.example;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;

public class AttributeExtractor {
    public void validateAssertionSignature(Assertion assertion) throws Exception {

        Signature signature;

        // Extract the Signature from the Assertion object
        try {
            signature = assertion.getSignature();
        } catch (Exception e) {
            throw new Exception("The signature is missing");
        }

        if(assertion.getSignature() == null){
            throw new Exception("The signature is null");
        }

        try {

            X509Data x509Data = (assertion.getSignature().getKeyInfo().getX509Datas()).get(0);
            X509Certificate x509Certificate = x509Data.getX509Certificates().get(0);
            byte[] publicBytes = Base64.decodeBase64(x509Certificate.getValue().replace(" ", ""));
            InputStream inputStream = new ByteArrayInputStream(publicBytes);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(inputStream);

            // Extract the PublicKey from the X509 Certificate present in the Assertion
            PublicKey publicKey = cert.getPublicKey();

            System.out.println(publicKey.toString());

            // Validate the Signature
            BasicX509Credential publicCredential = new BasicX509Credential();
            publicCredential.setPublicKey(publicKey);
            SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
            signatureValidator.validate(signature);
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("The Signature is invalid");
        }
    }
}

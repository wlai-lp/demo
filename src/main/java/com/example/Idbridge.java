package com.example;

// import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.ssl.PKCS8Key;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.Base64;
import javax.xml.XMLConstants;

public class Idbridge {
    
    String base64saml;
    private static final String UTF8 = "UTF-8";

    public void setSaml(String base64saml){
        this.base64saml = base64saml;
    }

    public void start(){
        try {
            String decodedSamlResp = decodeAndInflate(this.base64saml);
            System.out.println(decodedSamlResp);
            // Convert the SAMLResponse String to a Document
            Document samlResponseDocument = convertSamlToDocument(decodedSamlResp);

            Assertion assertion = extractAssertionFromSamlResponse(samlResponseDocument);
            

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private Assertion extractAssertionFromSamlResponse(Document document){
        Assertion decryptedAssertion = null;

        // If the document is null, return
        if (document == null) {
            return decryptedAssertion;
        }

        try {
            // Cast the Document to a Response object
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            XMLObject responseXmlObj = unmarshaller.unmarshall(element);
            Response response = (Response) responseXmlObj;




            if (CollectionUtils.isNotEmpty(response.getEncryptedAssertions())) {
                EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);

                // Create the credential
                BasicX509Credential decryptionCredential = new BasicX509Credential();
                // decryptionCredential.setPrivateKey(rsaPrivateKey);
                // log.debug("IdentityBridge: Credentials created");

                StaticKeyInfoCredentialResolver skicr = new StaticKeyInfoCredentialResolver(decryptionCredential);

                // Decrypt the Assertion
                Decrypter decrypter = new Decrypter(null, skicr, new InlineEncryptedKeyResolver());

                // In order to validate the Assertion (which was extracted from the Response), you MUST
                // reset the root of the document.  Otherwise the signature validation will fail.
                // Do NOT delete the line below
                decrypter.setRootInNewDocument(true);

                // log.debug("IdentityBridge: decrypter constructor");

                try {
                    decryptedAssertion = decrypter.decrypt(encryptedAssertion);
                } catch (DecryptionException de) {
                    // log.debug("IdentityBridge: Assertion decryption failed.");
                    // log.debug(IDENTITYBRIDGE_HEADER + de.getMessage());
                    throw de;
                }

                // log.debug("IdentityBridge: Assertion decryption succeeded.");
            }else{
                if (CollectionUtils.isNotEmpty(response.getAssertions())) {
                    decryptedAssertion = response.getAssertions().get(0);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("The Assertion could not be extracted");
        }

        return decryptedAssertion;
    }

    private Document convertSamlToDocument(String samlResponse) throws Exception {

        Document resp = null;
        String decodedSamlResponse;

        try {
            // Base64 decode the string if needed
            try {
                decodedSamlResponse = new String(java.util.Base64.getDecoder().decode(samlResponse));
            } catch (IllegalArgumentException iae) {
                // log.debug("IdentityBridge: The SAMLResponse is not Base64 encoded");
                decodedSamlResponse = samlResponse;
            }

            resp = safeDocFactory().newDocumentBuilder().parse(new InputSource(new StringReader(decodedSamlResponse)));
        
        } catch (Exception e) {
            e.printStackTrace();
        }

        return resp;
    }

    public static DocumentBuilderFactory safeDocFactory() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setAttribute("http://xml.org/sax/features/external-general-entities", false);
        factory.setAttribute("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setAttribute("http://javax.xml.XMLConstants/feature/secure-processing", true);
        factory.setAttribute("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return factory;
    }

    private String decodeAndInflate(String data) throws Exception {
        try {
            // Base64 decode
            org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
            byte[] xmlBytes = data.getBytes(UTF8);
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

            // Inflate (uncompress) the AuthnRequest data
            // First attempt to unzip the byte array according to DEFLATE (rfc 1951)
            Inflater inflater = new Inflater(true);
            inflater.setInput(base64DecodedByteArray);

            // since we are decompressing, it's impossible to know how much space we
            // might need; hopefully this number is suitably big
            byte[] xmlMessageBytes = new byte[5000];
            int resultLength = inflater.inflate(xmlMessageBytes);

            if (!inflater.finished()) {
                throw new Exception("Not Deflated");
            }

            inflater.end();

            return new String(xmlMessageBytes, 0, resultLength, UTF8);
        } catch (Exception e) {
            

            try {
                // It could be that the IdP has simply base64 encoded the SAML Response

                // Remove any line feeds
                String concatenatedData = data.replaceAll("\\n", "").replaceAll("\\r", "").replaceAll(" ", "");

                String decodedData = new String(Base64.getDecoder().decode(concatenatedData));
                if (decodedData.trim().startsWith("<")) {
                    // We can assume the SAML Response was just Base64 encoded
                    return decodedData;
                } else {
                    // log.debug("IdentityBridge: The item " + decodedData + " does not appear to be Base64 encoded");
                    throw new Exception("The SAMLResponse is not deflated or Base64 encoded, the data passed was" + decodedData);
                }
            } catch (IllegalArgumentException iae) {
                throw new Exception("The SAMLResponse is not deflated or Base64 encoded, the data passed was" + data);
            }
        }
    }
}

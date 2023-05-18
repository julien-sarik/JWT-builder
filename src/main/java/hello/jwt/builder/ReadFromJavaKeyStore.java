package hello.jwt.builder;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class ReadFromJavaKeyStore {

    public static void main(String[] args) throws Exception {
        // read RSA private key from keystore
        final String fileName = "src/main/resources/keystore.jks";
        final char[] storePass = "storepass".toCharArray();
        final String alias = "foo-client";
        final char[] keyPass = storePass;
        final KeyStore store = KeyStore.getInstance("JKS");
        final InputStream input = Files.newInputStream(Paths.get(fileName));
        store.load(input, storePass);
        final Certificate certificate = store.getCertificate(alias);
//        final java.security.interfaces.RSAKey key = (java.security.interfaces.RSAKey) store.getKey(alias, keyPass);

        // convert to nimbus key
        final RSAKey nimbusRsaKey = new RSAKey.Builder((RSAPublicKey) certificate.getPublicKey()).build();

        // build the JWS header
        final JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID("-RtrYV6X0U5WkXBGjbXDlb2APg8vkWY_hhFjQey3mrY")
                .build();

        // build the JWS payload
        final Map<String, Object> claims = new HashMap<>();
        claims.put("username", "admin");
        final String client_id = "45d8d6b6-de7c-449f-b7f7-b4e05ced432d";
        claims.put("iss", client_id);
        claims.put("sub", client_id);
        claims.put("aud", "https://api.fusionfabric.cloud/login/v1");
        claims.put("exp", System.currentTimeMillis() / 1000 + TimeUnit.HOURS.toSeconds(1));
        claims.put("jti", UUID.randomUUID().toString());

        // create signer from private key
        final JWSSigner signer = new RSASSASigner(nimbusRsaKey.toRSAKey());

        // signe the JWS
        final JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(claims));
        jwsObject.sign(signer);

        System.out.println(jwsObject.serialize());
    }

}

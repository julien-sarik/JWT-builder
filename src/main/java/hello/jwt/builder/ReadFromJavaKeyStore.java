package hello.jwt.builder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.Signer;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class ReadFromJavaKeyStore {

    private static final ObjectMapper MAPPER  = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        // read from RSA private key from keystore
        final String fileName = "/home/julien/projects/github/keystore/src/main/resources/keystore.jks";
        final char[] storePass = "p2".toCharArray();
        final String alias = "foo-client";
        final String keyPass = "p1";
        final KeyStore store = KeyStore.getInstance("JKS");
        final InputStream input = Files.newInputStream(Paths.get(fileName));
        store.load(input, storePass);
//        final Certificate entry = store.getCertificate(alias);
        final Key key = store.getKey(alias, keyPass.toCharArray());

        final Signer signer = rsaSigner((RSAPrivateKey) key);

        final ObjectNode content = MAPPER.createObjectNode();
        final String client_id = "371c28e3-e888-441a-b716-4a85b848d748";
        content.put("iss", client_id);
        content.put("sub", client_id);
        content.put("aud", "https://api.preprod.fusionfabric.cloud/login/v1");
        content.put("exp", System.currentTimeMillis() / 1000 + TimeUnit.HOURS.toSeconds(1));
        content.put("jti", UUID.randomUUID().toString());

        final Map<String, String> header = Collections.singletonMap("kid", "-RtrYV6X0U5WkXBGjbXDlb2APg8vkWY_hhFjQey3mrY");

        final Jwt jwt = createJwt(content, header, signer);

        final String jwtString = jwt.getEncoded();
        System.out.println(jwtString);
    }

    private static Signer rsaSigner(RSAPrivateKey privateKey) {
        return new RsaSigner(privateKey);
    }

    private static Signer macSigner(String secret) {
        return new MacSigner(secret);
    }

    private static Jwt createJwt(ObjectNode content, Map<String, String> jwtHeader, Signer signer) {
        try {
            return JwtHelper.encode(MAPPER.writeValueAsString(content), signer, jwtHeader);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}

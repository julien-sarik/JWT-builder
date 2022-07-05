package hello.jwt.builder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.Signer;

import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class ReadFromPem {

    private static final ObjectMapper MAPPER  = new ObjectMapper();
    private static final String KEY_FILE = "src/main/resources/private.pem";

    public static void main(String[] args) throws Exception {
        // read PEM file
        PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(KEY_FILE)));
        PEMKeyPair pemKeyPair = (PEMKeyPair)pemParser.readObject();
        // Convert to Java (JCA) format
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        KeyPair keyPair = converter.getKeyPair(pemKeyPair);
        pemParser.close();

        final Signer signer = rsaSigner((RSAPrivateKey) keyPair.getPrivate());

        final ObjectNode content = MAPPER.createObjectNode();
        final String client_id = "45d8d6b6-de7c-449f-b7f7-b4e05ced432d";
        content.put("iss", client_id);
        content.put("sub", client_id);
        content.put("aud", "https://api.fusionfabric.cloud/login/v1");
        content.put("exp", System.currentTimeMillis() / 1000 + TimeUnit.HOURS.toSeconds(1));
        content.put("jti", Long.toString(System.currentTimeMillis()));
        final Map<String, String> header = Collections.singletonMap("kid", "-RtrYV6X0U5WkXBGjbXDlb2APg8vkWY_hhFjQey3mrY");

        final Jwt jwt = createJwt(content, header, signer);
        final String jwtString = jwt.getEncoded();
        System.out.println(jwtString);
    }

    private static Signer rsaSigner(RSAPrivateKey privateKey) {
        return new RsaSigner(privateKey, "SHA256withRSA");
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

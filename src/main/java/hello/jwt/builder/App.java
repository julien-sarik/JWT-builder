package hello.jwt.builder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.Signer;

import java.util.Collections;
import java.util.Map;

public class App {

    private static final ObjectMapper MAPPER  = new ObjectMapper();
    private static final Signer SIGNER  = new MacSigner("secret");

    public static void main(String[] args) {
        final ObjectNode content = MAPPER.createObjectNode();
        content.put("aud", "a");
        content.putArray("roles").add("admin");
        content.put("sub", "app");
        content.put("exp", "1613398398");
        content.put("jti", System.currentTimeMillis());
        final Jwt jwt = createJwt(content, Collections.singletonMap("kid", "-RtrYV6X0U5WkXBGjbXDlb2APg8vkWY_hhFjQey3mrY"));
        final String jwtString = jwt.getEncoded();
        System.out.println(jwtString);
    }

    private static Jwt createJwt(ObjectNode content, Map<String, String> jwtHeader) {
        try {
            return JwtHelper.encode(MAPPER.writeValueAsString(content), SIGNER, jwtHeader);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}

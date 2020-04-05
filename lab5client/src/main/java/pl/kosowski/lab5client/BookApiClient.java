package pl.kosowski.lab5client;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.xml.bind.DatatypeConverter;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.stream.Stream;

@Controller
public class BookApiClient {

    public BookApiClient() throws Exception {
        addBooks(true);
        getBooks(true);
    }

    private void getBooks(boolean admin) throws Exception {
        String jwt = generateJwt(admin);
        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + jwt);
        HttpEntity httpEntity = new HttpEntity(headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String[]> exchange = restTemplate.exchange("http://localhost:8080/api/books",
                HttpMethod.GET,
                httpEntity,
                String[].class);
        Stream.of(exchange.getBody()).forEach(System.out::println);
    }

    private void addBooks(boolean admin) throws Exception {
        String jwt = generateJwt(admin);
        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + jwt);
        String bookToAdd = "New book";
        HttpEntity httpEntity = new HttpEntity(bookToAdd, headers);
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.exchange("http://localhost:8080/api/books",
                HttpMethod.POST,
                httpEntity,
                Void.class);
    }

    private String generateJwt(boolean isAdmin) throws Exception {
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) getPublicKey(), (RSAPrivateKey) getPrivateKey());
        return JWT.create().withClaim("admin", isAdmin).sign(algorithm);
    }

    PrivateKey getPrivateKey() throws Exception {
        Resource resource = new ClassPathResource("private_key.ppk");
        byte[] keyBytes = Files.readAllBytes(resource.getFile().toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    private PublicKey getPublicKey() throws Exception {
        String key = "---- BEGIN SSH2 PUBLIC KEY ----\n" +
                "Comment: \"rsa-key-20200405\"\n" +
                "AAAAB3NzaC1yc2EAAAABJQAAAQEAlvDJI1tH62eXLwtYT1FnhsC25rBdI8ZhdGr3\n" +
                "TtHkO7U8BnWvI/VXqviiBXFTVEUrLsAVGlgMdv5Zck7iznyZI2BGDu/hZCfVEdDv\n" +
                "3nenRkbKRvPICRujp6uiLoHxqu1m2jHNV6a5ZQZFMupe5lOM5dCdvNDv0NnFEusB\n" +
                "jUdVk+lsklZ65BsI144VJDh0bTbLPJu7V1paTeTI09d0YUc+9ZZOGDd97zPDwc+c\n" +
                "uuHiDq4q+RjuG38elZ3PpaTVXU/QlEnwscC0PRxSqy9Utt5+4pKoqymWnL78UFrF\n" +
                "FYX5iTaRgQQSi3mD+RvNDcArlVW4xB3N+bqME0MKF6eWuIf03Q==\n" +
                "---- END SSH2 PUBLIC KEY ----\n";
        byte[] derPublicKey = DatatypeConverter.parseHexBinary(key);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(derPublicKey);
        return keyFactory.generatePublic(publicKeySpec);
    }
}
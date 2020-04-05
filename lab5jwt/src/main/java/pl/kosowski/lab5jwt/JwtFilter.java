package pl.kosowski.lab5jwt;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;

public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String authorization = httpServletRequest.getHeader("Authorization");
        UsernamePasswordAuthenticationToken authenticationToken = null;
        try {
            authenticationToken = getUsernamePasswordAuthenticationToken(authorization);
        } catch (Exception e) {
            e.printStackTrace();
        }
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String authorization) throws Exception{
        SignedJWT signedJWT = SignedJWT.parse(authorization.substring(7));
        RSAKey publicKey = new RSAKey.Builder((RSAPublicKey) getPublicKey()).build();
        JWSVerifier jwsVerifier = new RSASSAVerifier(publicKey);
        if (!signedJWT.verify(jwsVerifier)) {
            throw new Exception();
        }

        String name = signedJWT.getJWTClaimsSet().getSubject();
        boolean isAdmin = signedJWT.getJWTClaimsSet().getBooleanClaim("admin");
        String role = "ROLE_USER";
        if (isAdmin)
            role = "ROLE_ADMIN";
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(role);
        return new UsernamePasswordAuthenticationToken(name, null, Collections.singleton(simpleGrantedAuthority));
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

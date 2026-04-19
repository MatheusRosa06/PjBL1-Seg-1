package com.pucpr.service;
import com.pucpr.model.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtService {

    // TODO: O ALUNO DEVE BUSCAR DE UMA VARIÁVEL DE AMBIENTE (System.getenv)
    // A chave deve ter pelo menos 256 bits (32 caracteres) para o algoritmo HS256.
    private final String SECRET_KEY = "sua_chave_secreta_com_pelo_menos_32_caracteres_aqui";

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    /**
     * Gera o token assinado.
     * 1. Define o 'subject' (e-mail do usuário).
     * 2. Adiciona Claims customizadas (como o 'role').
     * 3. Define a data de emissão e expiração (ex: 15 min).
     * 4. Assina com a chave e o algoritmo HS256.
     */
    public String generateToken(Usuario user) {
        // Exemplo de implementação que eles podem seguir ou completar
        String secret = System.getenv("JWT_SECRET"); // Ensinar boas práticas!
        return Jwts.builder()
                .subject(user.getEmail())
                .claim("role", user.getRole())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900000)) // 15 min
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()))
                .compact();
    }

    /**
     * Extrai o e-mail (subject) do token.
     * TODO: O ALUNO DEVE IMPLEMENTAR:
     * 1. Usar Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).
     * 2. Retornar o Subject do Payload.
     */
    public String extractEmail(String token) {
        return null;
        //Seu código aqui
    }

    /**
     * Valida se o token é autêntico e não expirou.
     * TODO: O ALUNO DEVE IMPLEMENTAR:
     * 1. Tentar fazer o parse do token.
     * 2. Se o parse falhar (assinatura errada ou expirado), a biblioteca joga uma Exception.
     * 3. Retornar true se o token for válido e false caso capture uma exceção.
     */
    public boolean validateToken(String token) {
        // TODO: O ALUNO DEVE IMPLEMENTAR
        try {
            // 1. Use o Jwts.parser() para descriptografar o token usando a mesma SECRET_KEY da geração.
            // 2. A biblioteca JJWT joga uma exceção automaticamente se o token estiver expirado ou a assinatura for inválida.
            // 3. Se o parse ocorrer sem erros, o token é íntegro. Retorne true.
            return true;
        } catch (Exception e) {
            // 4. Capture exceções específicas (ExpiredJwtException, SignatureException) e logue o erro para debug.
            return false;
        }
    }

}

package com.clonair.back.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Se encarga de manejar la creación, validación y extracción de información de los tokens JWT.
 * Los "Claims" en esta clase representan la información contenida dentro de un token JWT.
 * */
@Service
public class JwtService {

    // La clave secreta utilizada para firmar los tokens JWT.
    private static final String SECRET_KEY="586E3272357538782F413F4428472B4B6250655368566B597033733676397924";

    /**
     * Método que recibe un objeto UserDetails y devuelve un token JWT.
     * Este método llama a otro método interno, que genera el token con cualquier extraClaims adicional proporcionado.
     * */
    public String getToken(UserDetails user) { //
        return getToken(new HashMap<>(), user);
    }

    /**
     * Este método crea un token JWT utilizando la librería io.jsonwebtoken.
     * Toma un mapa de Claims adicionales (opcional) y los detalles del usuario (UserDetails).
     * */
    private String getToken(Map<String,Object> extraClaims, UserDetails user) {
        return Jwts
                .builder()
                .setClaims(extraClaims) // Establece los Claims adicionales proporcionados.
                .setSubject(user.getUsername()) // Establece el sujeto del token como el nombre de usuario del objeto UserDetails.
                .setIssuedAt(new Date(System.currentTimeMillis())) // Establece la fecha de emisión del token como el momento actual.
                .setExpiration(new Date(System.currentTimeMillis()+ 1000L *1000*60*60*24)) // Establece la fecha de expiración del token como un día después de su emisión.
                .signWith(getKey(), SignatureAlgorithm.HS256) // Firma el token con el algoritmo de hash HS256 utilizando la clave secreta.
                .compact(); // Devuelve el token JWT compactado como una cadena.
    }

    /**
     * Este método se utiliza para obtener la clave para firmar el token.
     * Toma la clave secreta en formato Base64, la decodifica
     * y la convierte en un objeto Key que se utiliza para firmar el token con HMAC-SHA.
     * */
    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Este método extrae el nombre de usuario (subject) del token JWT.
     * Utiliza el método genérico getClaim para obtener el sujeto del token (Claims::getSubject).
     * Devuelve el nombre de usuario almacenado en el token.
     * */
    public String getUsernameFromToken(String token) {
        if (StringUtils.hasText(token)) {
            return getClaim(token, Claims::getSubject);
        }
        return null;
    }

    /**
     * Este método verifica la validez del token JWT.
     * Obtiene el nombre de usuario del token utilizando getUsernameFromToken.
     * Compara este nombre de usuario con el nombre de usuario del objeto UserDetails proporcionado como argumento.
     * Verifica si el token ha expirado utilizando isTokenExpired.
     * Devuelve true si el token es válido (el nombre de usuario coincide y el token no ha expirado).
     * */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        if (StringUtils.hasText(token)) {
            final String username = getUsernameFromToken(token);
            return (username != null && username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        }
        return false; // Retorna falso para tokens nulos o vacíos
    }

/* REVISAR
    public boolean isTokenValid(String token) {
        return (!isTokenExpired(token));
    }
*/
    /**
     * Este método devuelve todos los Claims almacenados en el token JWT.
     * Utiliza la librería io.jsonwebtoken para analizar el token,
     * verifica la firma con la clave correspondiente
     * y devuelve el cuerpo (body) del token, que contiene todos los Claims.
     * */
    private Claims getAllClaims(String token) {
        if (StringUtils.hasText(token)) {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        }
        return null;
    }

    /**
     * Este método genérico obtiene un Claim específico del token.
     * Utiliza el método getAllClaims para obtener todos los Claims del token
     * y luego aplica la función claimsResolver para obtener el Claim específico deseado.
     * Es genérico en su implementación, lo que permite obtener cualquier Claim del token.
     * */
    public <T> T getClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims=getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Este método obtiene la fecha(Date) de expiración del token.
     * Utiliza el método getClaim con Claims::getExpiration,
     * para obtener la fecha de expiración almacenada en el token.
     * */
    private Date getExpiration(String token){
        return getClaim(token, Claims::getExpiration);
    }

    /**
     * Este método verifica si el token ha expirado.
     * Utiliza getExpiration para obtener la fecha de expiración del token
     * y compara esa fecha con la fecha actual (new Date()).
     * Devuelve true si el token ha expirado.
     * */
    private boolean isTokenExpired(String token){
        return getExpiration(token).before(new Date());
    }

    public static String getUserIdFromToken(String token) {
        if (token != null && !token.isEmpty()) {
            SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
            return claims.getSubject(); // Devuelve el ID del usuario como Subject del token
        }
        return null;
    }
}

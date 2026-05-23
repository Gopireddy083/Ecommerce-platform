  package com.ecommerce.user_service.service;

  import java.util.Date;
  import java.util.HashMap;
  import java.util.Map;
  import java.util.function.Function;

  import javax.crypto.SecretKey;

  import org.springframework.beans.factory.annotation.Value;
  import org.springframework.security.core.userdetails.UserDetails;
  import org.springframework.stereotype.Service;

  import io.jsonwebtoken.Claims;
  import io.jsonwebtoken.Jwts;
  import io.jsonwebtoken.io.Decoders;
  import io.jsonwebtoken.security.Keys;

  @Service
  public class JwtService {

      @Value("${jwt.secret}")
      private String secretKey;

      @Value("${jwt.expiration}")
      private long expiration;

      public String generateToken(UserDetails userDetails) {
          Map<String, Object> claims = new HashMap<>();
          claims.put("role", userDetails.getAuthorities()
                  .iterator().next().getAuthority());
          return buildToken(claims, userDetails);
      }

      private String buildToken(Map<String, Object> claims, UserDetails userDetails) {
          return Jwts.builder()
                  .claims(claims)                                           // changed from setClaims()
                  .subject(userDetails.getUsername())                       // changed from setSubject()
                  .issuedAt(new Date(System.currentTimeMillis()))           // changed from setIssuedAt()
                  .expiration(new Date(System.currentTimeMillis() + expiration)) // changed from setExpiration()
                  .signWith(getSigningKey())                                // no need to pass algorithm
                  .compact();
      }

      public boolean isTokenValid(String token, UserDetails userDetails) {
          final String username = extractUsername(token);
          return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
      }

      public String extractUsername(String token) {
          return extractClaim(token, Claims::getSubject);
      }

      private boolean isTokenExpired(String token) {
          return extractExpiration(token).before(new Date());
      }

      private Date extractExpiration(String token) {
          return extractClaim(token, Claims::getExpiration);
      }

      public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
          final Claims claims = extractAllClaims(token);
          return claimsResolver.apply(claims);
      }

      private Claims extractAllClaims(String token) {
          return Jwts.parser()                          // changed from parserBuilder()
                  .verifyWith(getSigningKey())           // changed from setSigningKey()
                  .build()
                  .parseSignedClaims(token)             // changed from parseClaimsJws()
                  .getPayload();                        // changed from getBody()
      }

      private SecretKey getSigningKey() {
          byte[] keyBytes = Decoders.BASE64.decode(secretKey);
          return Keys.hmacShaKeyFor(keyBytes);
      }
  }
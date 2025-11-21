
Spring Security의 OAuth2 Resource Server 기능을 사용하여 Keycloak(또는 다른 OIDC/OAuth2 제공자)으로부터 발행된 JWT 액세스 토큰을 검증하고, 토큰 내부의 역할(role)을 Spring Security 권한(GrantedAuthority)으로 매핑해 API 엔드포인트 접근 제어를 수행합니다.

- 스프링 리소스 서버는 `jwk-set-uri` 또는 `issuer-uri`(OIDC discovery)를 통해 제공자에서 JWKS(JSON Web Key Set, 공개키 집합)를 가져옵니다.
- 가져온 공개키로 JWT의 서명을 검증(서명 검증)하고, `exp`, `nbf`, `aud` 등의 표준 클레임 유효성도 자동으로 검사합니다.
- JWT 내부에 포함된 역할(claim)은 자동으로 Spring 권한으로 변환되지 않기 때문에 별도의 변환기(Converter)가 필요합니다. 이 프로젝트에서는 `KeycloakRoleConverter`를 사용해 `realm_access.roles`와 `resource_access`의 모든 클라이언트 역할을 읽어 `ROLE_{role}` 형태의 GrantedAuthority로 변환합니다.

구성 예시 (application.yml)

```yaml
server:
  port: 8081

spring:
  security:
    oauth2:
      resourceserver:
        # Keycloak의 경우
        issuer-uri: http://localhost:8080/realms/myrealm
        jwk-set-uri: http://localhost:8080/realms/myrealm/protocol/openid-connect/certs

# 디버그 로그 (필요시)
logging:
  level:
    org.springframework.security.oauth2: DEBUG
```
**SecurityConfig — 코드 및 설명**

아래 `SecurityConfig`는 스프링 시큐리티를 JWT 기반 리소스 서버로 구성하고, `JwtAuthenticationConverter`에 커스텀 권한 변환기를 연결해 Keycloak 토큰의 역할을 Spring 권한으로 매핑합니다.

파일: `src/main/java/nuts/study/keycloakauth/oauth2resource/config/SecurityConfig.java`

```java
package nuts.study.keycloakauth.oauth2resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, KeycloakRoleConverter roleConverter) throws Exception {

        // JwtAuthenticationConverter 생성: JWT에서 Authentication 객체로 변환할 때 사용
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

        // 커스텀 Converter 주입: Jwt -> Collection<GrantedAuthority>
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(roleConverter);

        // HttpSecurity 설정
        http
                // 경로별 권한 정책 정의
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/admin/**").hasRole("admin")
                        .requestMatchers("/user/**").hasRole("user")
                        .anyRequest().permitAll()
                )
                // OAuth2 Resource Server 설정: JWT 검증 사용
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter)
                        )
                );
        return http.build();
    }
}
```

- `JwtAuthenticationConverter`는 JWT를 읽어 `Authentication` 객체(Principal, Authorities 등)로 바꿔준다.
- `setJwtGrantedAuthoritiesConverter`로 주입된 `roleConverter`는 JWT 전체를 파싱해 `GrantedAuthority` 목록을 반환한다.
- `oauth2ResourceServer().jwt()` 설정을 통해 스프링은 `jwk-set-uri`로부터 공개키를 가져와 JWT 서명(서명 검증) 및 기본 클레임 검증을 자동으로 수행한다.

KeycloakRoleConverter — 코드 및 설명

이 변환기는 Keycloak이 발행한 JWT의 중첩된 구조(`realm_access.roles`, `resource_access.{client}.roles`)를 파싱해 Spring 권한으로 변환합니다.

파일: `src/main/java/nuts/study/keycloakauth/oauth2resource/config/KeycloakRoleConverter.java`

```java
package nuts.study.keycloakauth.oauth2resource.config;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Component
public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<String> roles = new HashSet<>();

        // realm_access.roles 파싱
        Object realmAccess = jwt.getClaims().get("realm_access");
        if (realmAccess instanceof Map) {
            Object r = ((Map<?, ?>) realmAccess).get("roles");
            if (r instanceof List) {
                for (Object role : (List<?>) r) {
                    roles.add(String.valueOf(role));
                }
            }
        }

        // resource_access.*.roles 파싱: 모든 클라이언트의 roles를 수집
        Object resourceAccess = jwt.getClaims().get("resource_access");
        if (resourceAccess instanceof Map) {
            Map<?, ?> resourceMap = (Map<?, ?>) resourceAccess;
            for (Object clientObj : resourceMap.values()) {
                if (clientObj instanceof Map) {
                    Object cr = ((Map<?, ?>) clientObj).get("roles");
                    if (cr instanceof List) {
                        for (Object role : (List<?>) cr) {
                            roles.add(String.valueOf(role));
                        }
                    }
                }
            }
        }

        // ROLE_ 접두사 추가하여 GrantedAuthority 반환
        return roles.stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                .collect(Collectors.toList());
    }
}
```

1. 중첩된 claim 접근: 기본 `JwtGrantedAuthoritiesConverter`는 단일 claim 이름만 읽는 경우가 많아 `realm_access.roles` 같은 중첩 구조를 읽지 못합니다. 따라서 JWT 전체를 읽어 Map 구조를 직접 탐색합니다.
2. 여러 클라이언트 역할: `resource_access` 안에는 여러 클라이언트의 역할 정보가 들어올 수 있으므로 모든 클라이언트 항목을 순회해 역할을 수집합니다.
3. 권한 표준화: Spring Security의 `hasRole("admin")` 같은 API와 호환되도록 `ROLE_` 접두사를 붙여 `SimpleGrantedAuthority`로 반환합니다.

동작 흐름 요약

1. 클라이언트가 Keycloak에서 액세스 토큰을 발급받아 API 호출 시 `Authorization: Bearer <token>` 헤더로 보냅니다.
2. 스프링은 `jwk-set-uri`에서 JWKS를 가져와 토큰의 서명을 검증합니다(서명 검증).
3. 기본 클레임(`exp`, `aud`, 등) 체크 후, `JwtAuthenticationConverter`가 호출되어 `KeycloakRoleConverter`가 역할을 추출해 `Authentication` 객체로 변환합니다.
4. 스프링 시큐리티의 URL별 접근 규칙에 따라 접근 허용/거부가 결정됩니다.

사용 예시

- curl(예: 발급받은 액세스토큰을 환경변수 TOKEN에 저장한 경우)

```bash
curl -H "Authorization: Bearer ${TOKEN}" http://localhost:8081/user/hello
```
- Postman 등 API 클라이언트에서 Authorization 헤더에 Bearer 토큰을 설정하여 호출 가능합니다.
- Keycloak에서 발급된 토큰에 따라 `/admin/**`와 `/user/**` 경로 접근이 제어됩니다.
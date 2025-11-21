package nuts.study.keycloakauth.oauth2resource.config;

import java.util.ArrayList;
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

        // realm_access.roles 처리
        Object realmAccess = jwt.getClaims().get("realm_access");
        if (realmAccess instanceof Map) {
            Object r = ((Map<?, ?>) realmAccess).get("roles");
            if (r instanceof List) {
                for (Object role : (List<?>) r) {
                    roles.add(String.valueOf(role));
                }
            }
        }

        // resource_access.{client}.roles 처리 (모든 클라이언트의 roles 수집)
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

        // 반환: ROLE_ 접두사를 붙인 GrantedAuthority 목록
        return roles.stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                .collect(Collectors.toList());
    }
}


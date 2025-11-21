package nuts.study.keycloakauth.oauth2resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    // 현재 인증된 사용자 정보 반환
    @GetMapping("/get_auth_info")
    public Object getAuthInfo(java.security.Principal principal) {
        return principal;
    }

    @GetMapping("/user/hello")
    public String userHello() {
        return "Hello, User!";
    }

    @GetMapping("/admin/hello")
    public String adminHello() {
        return "Hello, Admin!";
    }
}

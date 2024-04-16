package org.cris6h16.springsecurity_csrf_mvn.Configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf((csrf) -> csrf
//                    .csrfTokenRepository(new HttpSessionCsrfTokenRepository()) // default
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // HttpOly = false, For let JS Frameworks read it.
//                    .csrfTokenRepository(new CookieCsrfTokenRepository()) //  If read the cookie with JS directly isn't necessary == improve security
                );
        return http.build();
    }
}

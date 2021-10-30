package com.tvmsoftware;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfiguration {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
      // @formatter:off
      http
          .authorizeRequests(authorizeRequests ->
              authorizeRequests.anyRequest().authenticated()
          )
          .formLogin(Customizer.withDefaults());
      // @formatter:on

        return http.build();
    }
}

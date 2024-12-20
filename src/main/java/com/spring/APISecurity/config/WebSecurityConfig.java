package com.spring.APISecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.web.SecurityFilterChain;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

    // Configuração de segurança
    @SuppressWarnings({ "removal" })
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .requestMatchers("/").permitAll() 
                .requestMatchers(HttpMethod.POST, "/login").permitAll() 
                .requestMatchers("/managers").hasAnyRole("MANAGERS") 
                .requestMatchers("/users").hasAnyRole("USERS", "MANAGERS") 
                .anyRequest().authenticated()  
                .and()
                .httpBasic();  

        return http.build();
    }

  
    @SuppressWarnings("removal")
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .inMemoryAuthentication()
                .withUser(User.withUsername("user").password("{noop}user123").roles("USERS").build())
                .withUser(User.withUsername("admin").password("{noop}admin123").roles("MANAGERS").build())
                .and()
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("user").password("{noop}user123").roles("USERS").build(),
                User.withUsername("admin").password("{noop}admin123").roles("MANAGERS").build()
        );
    }
}

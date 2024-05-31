package org.sendso.examplessecurityconfigurationadvanced.security;


import org.sendso.examplessecurityconfigurationadvanced.security.filters.JwtAuthenticationFilter;
import org.sendso.examplessecurityconfigurationadvanced.security.filters.JwtAuthorizationFilter;
import org.sendso.examplessecurityconfigurationadvanced.security.jwt.JwtUtils;
import org.sendso.examplessecurityconfigurationadvanced.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true) // habilitar las anotaciones en el controlador para las autorizaciones
public class SecurityConfig {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    JwtAuthorizationFilter authorizationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, AuthenticationManager authenticationManager) throws Exception {

        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtUtils);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager);
        // /login es la url que viene por defecto, si no la pusieramos seria la misma
        // setFilterProcessesUrl nos permite cambiarla aunque se podria omitir en este caso.
        jwtAuthenticationFilter.setFilterProcessesUrl("/login");

        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/hello").permitAll();
                    /*
                    * Se ha sutituido por las anotaciones en el controlador
                    auth.requestMatchers("/createuser").hasRole("ADMIN");
                    * */

                    auth.anyRequest().authenticated();
                })

                .sessionManagement(session -> {
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })

                .addFilter(jwtAuthenticationFilter)
                .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class)

                .build();

    }


    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }



    @Bean
    AuthenticationManager authenticationManager(HttpSecurity httpSecurity) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());

        return authenticationManagerBuilder.build();
    }



}

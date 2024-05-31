package org.sendso.examplessecurityconfigurationadvanced.security.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.sendso.examplessecurityconfigurationadvanced.security.jwt.JwtUtils;
import org.sendso.examplessecurityconfigurationadvanced.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String tokenHeader = request.getHeader("Authorization");

        if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
            String token = tokenHeader.substring(7);

            if(jwtUtils.isTokenValid(token)){
                // recuperar el username del token
                String username = jwtUtils.getUsernameFromToken(token);
                // recuperar mediante el username todos los detalles desde la base de datos
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                // nos autenticamos
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                userDetails.getAuthorities()
                        );
                // Recuperamos la autenticacion que habiamos hechio previamente y la seteamos con los roles que tiene.
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            }
        }
        filterChain.doFilter(request,response);
    }
}

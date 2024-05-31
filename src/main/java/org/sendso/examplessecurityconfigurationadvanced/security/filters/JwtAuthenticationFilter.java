package org.sendso.examplessecurityconfigurationadvanced.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.sendso.examplessecurityconfigurationadvanced.models.UserEntity;
import org.sendso.examplessecurityconfigurationadvanced.security.jwt.JwtUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private JwtUtils jwtUtils;

    public JwtAuthenticationFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        UserEntity userEntity = null;
        String username = "";
        String password = "";
        try {
            // usuario y contraseña ya vienen en la paticion(request) pero viene en formato json
            // Usando la libreria jackson mapeamos el json a un objeto de la clase UserEntity
            userEntity = new ObjectMapper().readValue(request.getInputStream(), UserEntity.class);
            username = userEntity.getUsername();
            password = userEntity.getPassword();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);


        return getAuthenticationManager().authenticate(authenticationToken);
    }

    // Si la autenticacion es correcta con este metodo generamos el token.
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        User user = (User) authResult.getPrincipal();

        // Generar el token de acceso
        String token = jwtUtils.generarAccesToken(user.getUsername());

        response.addHeader("Authorization", token);
        Map<String, Object> httpResponse = new HashMap<>();
        httpResponse.put("token", token);
        httpResponse.put("Message", "Autenticacion correcta");
        httpResponse.put("Username", user.getUsername());

        response.getWriter().write(new ObjectMapper().writeValueAsString(httpResponse));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().flush();

        super.successfulAuthentication(request, response, chain, authResult);

    }
}

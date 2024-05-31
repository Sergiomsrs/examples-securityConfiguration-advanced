package org.sendso.examplessecurityconfigurationadvanced.controller;

import jakarta.validation.Valid;
import org.sendso.examplessecurityconfigurationadvanced.controller.request.CreateUserDto;
import org.sendso.examplessecurityconfigurationadvanced.models.ERole;
import org.sendso.examplessecurityconfigurationadvanced.models.RoleEntity;
import org.sendso.examplessecurityconfigurationadvanced.models.UserEntity;
import org.sendso.examplessecurityconfigurationadvanced.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class PrincipalController {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    @GetMapping("/hello")
    public String hello() {
        return "Hello World Not Secured";
    }

    @GetMapping("/hellosecured")
    public String helloSecured() {
        return "Hello World Secured";
    }

    @PostMapping("/createuser")
    @PreAuthorize("hasRole('ADMIN')")
   // @PreAuthorize("hasAnyRole('ADMIN','USER')")
    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserDto createUserDto) {
        //Creamos el usurio que viene por el cuerpo de la peticion
        // podemos hacerlo asi gracias a que UserEntity esta anotada con @Builder de lombock

        // Los roles vienen como Set de String y hay que convertirlos a roles de la clase Erole que es un enum
        // mediante un map convertimos a Erole el valor del string mediante la api stream.

        Set<RoleEntity> roles = createUserDto.getRoles().stream()
                .map(role -> RoleEntity.builder()
                        .name(ERole.valueOf(role))
                        .build()).collect(Collectors.toSet());

        UserEntity userEntity = UserEntity.builder()
                .username(createUserDto.getUsername())
                .password(passwordEncoder.encode(createUserDto.getPassword()))
                .email(createUserDto.getEmail())
                .roles(roles)
                .build();
        userRepository.save(userEntity);

        return ResponseEntity.ok(userEntity);
    }

    @DeleteMapping("/deleteuser")
    public String deleteUser(@RequestParam String id) {
        userRepository.deleteById(Long.parseLong(id));
        return "Se ha borrado el user con el id".concat(id);
    }
}

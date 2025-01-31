package org.sendso.examplessecurityconfigurationadvanced;

import org.sendso.examplessecurityconfigurationadvanced.models.ERole;
import org.sendso.examplessecurityconfigurationadvanced.models.RoleEntity;
import org.sendso.examplessecurityconfigurationadvanced.models.UserEntity;
import org.sendso.examplessecurityconfigurationadvanced.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@SpringBootApplication
public class ExamplesSecurityConfigurationAdvancedApplication {

    public static void main(String[] args) {
        SpringApplication.run(ExamplesSecurityConfigurationAdvancedApplication.class, args);
    }

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    @Bean
    CommandLineRunner init(){
        return args -> {
            UserEntity userEntity = UserEntity.builder()
                    .email("ross@correo.com")
                    .username("ross")
                    .password(passwordEncoder.encode("1234"))
                    .roles(Set.of(RoleEntity.builder().name(ERole.valueOf(ERole.ADMIN.name())).build()))
                    .build();

            UserEntity userEntity2 = UserEntity.builder()
                    .email("rachel@correo.com")
                    .username("rachel")
                    .password(passwordEncoder.encode("1234"))
                    .roles(Set.of(RoleEntity.builder().name(ERole.valueOf(ERole.USER.name())).build()))
                    .build();

            UserEntity userEntity3 = UserEntity.builder()
                    .email("monica@correo.com")
                    .username("monica")
                    .password(passwordEncoder.encode("1234"))
                    .roles(Set.of(RoleEntity.builder().name(ERole.valueOf(ERole.INVITED.name())).build()))
                    .build();
            userRepository.save(userEntity);
            userRepository.save(userEntity2);
            userRepository.save(userEntity3);
        };
    }

}

package org.sendso.examplessecurityconfigurationadvanced.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data // crea los getter y setter
@AllArgsConstructor // crea constructor con todos los atributos
@NoArgsConstructor // crea constructor sin atributos
@Builder // crea metodo para crear objetos de la clase mediante el patron builder
// estas anotaciones son de lombok
@Entity // Convierte la clase en una clase entidad
@Table(name = "users") // asigna el nombre users a la tabla, si no se pone seria el mismo nombre de la clase
public class UserEntity {

    @Id // anota el atributo como identificador unico
    @GeneratedValue(strategy = GenerationType.IDENTITY) // JPA genera el id automaticamente
    private Long id;

    @Email //valida que se inserte un email valido
    @NotBlank
    @Size(max = 80)
    private String email;

    @NotBlank
    @Size(max = 30)
    private String username;

    @NotBlank
    private String password;

    @ManyToMany(fetch = FetchType.EAGER, targetEntity = RoleEntity.class, cascade = CascadeType.PERSIST)
    // Configuramos la tabla intermedia que se va a crear entre user y role
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name= "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"
    ))
    private Set<RoleEntity> roles;
}

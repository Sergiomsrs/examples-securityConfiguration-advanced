package org.sendso.examplessecurityconfigurationadvanced.repositories;

import org.apache.catalina.User;
import org.sendso.examplessecurityconfigurationadvanced.models.UserEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserEntity,Long> {


    Optional<UserEntity> findByUsername(String username);


}

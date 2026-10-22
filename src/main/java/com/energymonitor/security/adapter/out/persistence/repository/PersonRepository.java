package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.PersonEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code person}.
 */
@Repository
public interface PersonRepository extends JpaRepository<PersonEntity, String> {
}
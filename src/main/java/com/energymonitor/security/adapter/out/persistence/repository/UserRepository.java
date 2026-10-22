package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.UserEntity;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code user}.
 */
@Repository
public interface UserRepository extends JpaRepository<UserEntity, String> {

    /**
     * Finds the active account whose normalised email matches.
     *
     * @param email the normalised email
     * @return the account, empty when soft-deleted or unknown
     */
    Optional<UserEntity> findByEmailAndDeletedAtIsNull(String email);

    Optional<UserEntity> findByGoogleSubjectAndDeletedAtIsNull(String googleSubject);

    /**
     * Lists the active accounts with their person, newest first.
     *
     * @param pattern a lower-case {@code LIKE} pattern over address, name and last name, or
     *                {@code null} for every account
     * @param pageable the page
     * @return the page of rows
     */
    @Query(value = """
            select new com.energymonitor.security.adapter.out.persistence.repository.UserDirectoryRow(
                u.idUser, u.email, p.name, p.lastName, u.status, u.emailVerified,
                u.registrationDate, u.lastLoginAt)
            from UserEntity u, PersonEntity p
            where p.idPerson = u.personId and u.deletedAt is null
              and (:pattern is null or lower(u.email) like :pattern
                   or lower(p.name) like :pattern or lower(p.lastName) like :pattern)
            order by u.registrationDate desc, u.idUser
            """,
            countQuery = """
            select count(u) from UserEntity u, PersonEntity p
            where p.idPerson = u.personId and u.deletedAt is null
              and (:pattern is null or lower(u.email) like :pattern
                   or lower(p.name) like :pattern or lower(p.lastName) like :pattern)
            """)
    Page<UserDirectoryRow> searchDirectory(@Param("pattern") String pattern, Pageable pageable);
}

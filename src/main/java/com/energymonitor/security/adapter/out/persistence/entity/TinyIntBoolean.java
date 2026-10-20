package com.energymonitor.security.adapter.out.persistence.entity;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Marks a {@code boolean} attribute as backed by a MySQL {@code tinyint(1)} column.
 *
 * <p>Liquibase creates every boolean in the Security schema with type {@code BOOLEAN}, which
 * MySQL materialises as {@code tinyint(1)}. Hibernate, however, assumes a plain
 * {@code boolean} attribute maps to {@code bit}, and with {@code ddl-auto=validate} that
 * assumption fails the context startup with
 * {@code found [tinyint (Types#TINYINT)], but expecting [bit (Types#BOOLEAN)]}.
 *
 * <p>Declaring the real JDBC type keeps the mapping honest about what is in the database
 * without touching the schema. The alternative, flipping the columns to {@code bit} in
 * Liquibase, is not available: the schema is fixed and is the source of truth.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD})
@JdbcTypeCode(SqlTypes.TINYINT)
public @interface TinyIntBoolean {
}

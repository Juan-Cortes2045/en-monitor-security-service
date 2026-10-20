package com.energymonitor.security.application.port.out;

/**
 * Output port for generating the {@code VARCHAR(10)} business identifiers used across the
 * security aggregates.
 */
public interface IdentifierGeneratorPort {

    /**
     * Generates a new identifier fitting the {@code VARCHAR(10)} columns.
     *
     * @return a non-blank, at most 10 character identifier
     */
    String generate();
}
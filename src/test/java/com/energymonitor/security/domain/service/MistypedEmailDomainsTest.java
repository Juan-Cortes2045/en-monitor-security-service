package com.energymonitor.security.domain.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("Mistyped email domains")
class MistypedEmailDomainsTest {

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
            "meil.com, mail.com",
            "gmial.com, gmail.com",
            "gmal.com, gmail.com",
            "gnail.com, gmail.com",
            "gmail.co, gmail.com",
            "gmail.con, gmail.com",
            "gmial.con, gmail.com",
            "GMAIL.CM, gmail.com",
            "hotmial.com, hotmail.com",
            "hotmail.co, hotmail.com",
            "hotmal.es, hotmail.es",
            "outlok.com, outlook.com",
            "yaho.com, yahoo.com",
            "iclod.com, icloud.com",
            "misena.edu.cp, misena.edu.co",
            "sena.edu.con, sena.edu.co"
    })
    @DisplayName("suggests the provider a slip of the finger was aiming at")
    void suggestsTheIntendedProvider(String typed, String provider) {
        assertThat(MistypedEmailDomains.intendedProvider(typed)).contains(provider);
    }

    @ParameterizedTest
    @ValueSource(strings = {"gmail.com", "hotmail.es", "mail.com", "email.com", "ymail.com",
            "aol.com", "me.com", "soy.sena.edu.co", "misena.edu.co"})
    @DisplayName("accepts the providers themselves")
    void acceptsTheProviders(String provider) {
        assertThat(MistypedEmailDomains.intendedProvider(provider)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "energy-monitor.tech", "unal.edu.co", "udea.edu.co",
            "empresa.com.co", "aon.com", "gmx.de", "yahoo.com.mx", "gmail.com.co"})
    @DisplayName("leaves every other domain to the DNS check")
    void leavesOtherDomainsAlone(String domain) {
        assertThat(MistypedEmailDomains.intendedProvider(domain)).isEmpty();
    }

    @Test
    @DisplayName("counts a swap of two neighbouring letters as one edit")
    void countsASwapAsOneEdit() {
        assertThat(MistypedEmailDomains.distance("gmial", "gmail")).isEqualTo(1);
        assertThat(MistypedEmailDomains.distance("meil", "mail")).isEqualTo(1);
        assertThat(MistypedEmailDomains.distance("gmail", "gmail")).isZero();
    }
}

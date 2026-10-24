package com.energymonitor.security.adapter.out.dns;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import org.junit.jupiter.api.Test;

/** Only a definite answer refuses an address; an unreachable resolver lets it through. */
class DnsEmailDomainCheckAdapterTest {

    private static DnsEmailDomainCheckAdapter answering(Map<String, List<String>> records) {
        return new DnsEmailDomainCheckAdapter((domain, types) -> records);
    }

    @Test
    void acceptsADomainWithAMailServer() {
        assertThat(answering(Map.of("MX", List.of("5 gmail-smtp-in.l.google.com."), "A", List.of("1.2.3.4")))
                .acceptsMail("gmail.com")).isTrue();
    }

    @Test
    void acceptsADomainWithOnlyAnAddress() {
        // Without MX, mail is delivered to the address of the domain itself.
        assertThat(answering(Map.of("A", List.of("1.2.3.4"))).acceptsMail("pequeno.org")).isTrue();
    }

    @Test
    void refusesADomainThatDeclaresItTakesNoMail() {
        // example.com: an address, but a null MX ("0 .", RFC 7505).
        assertThat(answering(Map.of("MX", List.of("0 ."), "A", List.of("172.66.147.243")))
                .acceptsMail("example.com")).isFalse();
    }

    @Test
    void aRealMailServerNextToANullMxStillCounts() {
        assertThat(answering(Map.of("MX", List.of("0 .", "10 mx.dominio.org."))).acceptsMail("dominio.org"))
                .isTrue();
    }

    @Test
    void refusesADomainThatDoesNotExist() {
        DnsEmailDomainCheckAdapter check = new DnsEmailDomainCheckAdapter((domain, types) -> {
            throw new NameNotFoundException(domain);
        });

        assertThat(check.acceptsMail("gmial.con")).isFalse();
    }

    @Test
    void refusesADomainWithNoMailServerNorAddress() {
        assertThat(answering(Map.of()).acceptsMail("vacio.test")).isFalse();
    }

    @Test
    void letsTheAddressThroughWhenDnsCannotBeReached() {
        DnsEmailDomainCheckAdapter check = new DnsEmailDomainCheckAdapter((domain, types) -> {
            throw new CommunicationException("timeout");
        });

        assertThat(check.acceptsMail("gmail.com")).isTrue();
    }

    @Test
    void asksForMailServersAndAddressesInLowerCase() {
        String[] asked = new String[1];
        new DnsEmailDomainCheckAdapter((domain, types) -> {
            asked[0] = domain;
            assertThat(types).containsExactlyInAnyOrder("MX", "A", "AAAA");
            return Map.of("MX", List.of("5 mx.gmail.com."));
        }).acceptsMail("GMail.COM");

        assertThat(asked[0]).isEqualTo("gmail.com");
    }

    /** Against the real resolver, when there is one: skipped without network. */
    @Test
    void readsRealRecords() {
        assumeTrue(resolves("gmail.com"), "no DNS");
        DnsEmailDomainCheckAdapter check = DnsEmailDomainCheckAdapter.usingSystemResolver(Duration.ofSeconds(3));

        assertThat(check.acceptsMail("gmail.com")).isTrue();
        assertThat(check.acceptsMail("example.com")).isFalse();
        assertThat(check.acceptsMail("gmial.con")).isFalse();
    }

    private static boolean resolves(String host) {
        try {
            InetAddress.getByName(host);
            return true;
        } catch (UnknownHostException offline) {
            return false;
        }
    }
}

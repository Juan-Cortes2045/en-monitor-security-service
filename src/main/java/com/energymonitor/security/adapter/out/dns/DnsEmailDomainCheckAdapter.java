package com.energymonitor.security.adapter.out.dns;

import com.energymonitor.security.application.port.out.EmailDomainCheckPort;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Asks DNS whether a domain can receive mail: it must exist and publish a mail server (MX) or, as
 * the mail standard allows, an address (A or AAAA) to deliver to.
 *
 * <p>A domain whose only mail server is the "null MX" ({@code 0 .}, RFC 7505) declares that it
 * accepts no mail at all, whatever addresses it has: refused. That is what {@code example.com} and
 * the other names reserved for documentation publish.
 *
 * <p>Only a definite answer refuses: a domain that does not exist, or one with none of those
 * records. A timeout or an unreachable resolver lets the address through - the verification code
 * still has to arrive - because an outage of DNS must not stop people from registering.
 */
public class DnsEmailDomainCheckAdapter implements EmailDomainCheckPort {

    private static final Logger LOG = LoggerFactory.getLogger(DnsEmailDomainCheckAdapter.class);
    private static final Set<String> MAIL_RECORDS = Set.of("MX", "A", "AAAA");

    /** The records a domain publishes, by type, among the types asked for. */
    @FunctionalInterface
    public interface DnsLookup {
        Map<String, List<String>> records(String domain, Set<String> types) throws NamingException;
    }

    private final DnsLookup lookup;

    public DnsEmailDomainCheckAdapter(DnsLookup lookup) {
        this.lookup = lookup;
    }

    /** @param timeout how long to wait for the resolver before letting the address through */
    public static DnsEmailDomainCheckAdapter usingSystemResolver(Duration timeout) {
        return new DnsEmailDomainCheckAdapter((domain, types) -> {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("com.sun.jndi.dns.timeout.initial", String.valueOf(timeout.toMillis()));
            env.put("com.sun.jndi.dns.timeout.retries", "1");
            InitialDirContext context = new InitialDirContext(env);
            try {
                // One query per type: asked together, the provider drops a null MX ("0 .") and
                // answers only the addresses, which would make example.com look deliverable.
                Map<String, List<String>> found = new HashMap<>();
                for (String type : types) {
                    Attributes attributes = context.getAttributes(domain, new String[] {type});
                    NamingEnumeration<? extends Attribute> all = attributes.getAll();
                    while (all.hasMore()) {
                        Attribute attribute = all.next();
                        List<String> values = new ArrayList<>();
                        NamingEnumeration<?> each = attribute.getAll();
                        while (each.hasMore()) {
                            values.add(String.valueOf(each.next()).trim());
                        }
                        if (!values.isEmpty()) {
                            found.put(attribute.getID().toUpperCase(Locale.ROOT), values);
                        }
                    }
                }
                return found;
            } finally {
                context.close();
            }
        });
    }

    @Override
    public boolean acceptsMail(String domain) {
        String name = domain.toLowerCase(Locale.ROOT);
        try {
            Map<String, List<String>> records = lookup.records(name, MAIL_RECORDS);
            List<String> mailServers = records.getOrDefault("MX", List.of());
            if (!mailServers.isEmpty()) {
                // Any real mail server will do; a null MX alone means "no mail here".
                return !mailServers.stream().allMatch(DnsEmailDomainCheckAdapter::isNullMx);
            }
            return records.containsKey("A") || records.containsKey("AAAA");
        } catch (NameNotFoundException noSuchDomain) {
            return false;
        } catch (NamingException | RuntimeException unavailable) {
            LOG.warn("Could not check the mail domain {}; letting it through: {}", name,
                    unavailable.toString());
            return true;
        }
    }

    /** {@code 0 .}: preference 0 and the root as host, the RFC 7505 "this domain takes no mail". */
    private static boolean isNullMx(String mxRecord) {
        String[] parts = mxRecord.trim().split("\\s+");
        return parts.length == 2 && parts[1].equals(".");
    }
}

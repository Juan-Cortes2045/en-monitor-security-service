package com.energymonitor.security.domain.service;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Recognises a mail domain that is one or two keystrokes away from a well-known provider, such as
 * {@code meil.com}, {@code gmial.con} or {@code hotmail.co}.
 *
 * <p>DNS alone cannot catch these: many of them are registered on purpose and publish real mail
 * servers that collect whatever is sent to them, so they look deliverable. The account would then
 * be created for an address its owner never reads, and the verification code would land with a
 * stranger. A domain this close to a provider is almost always a slip of the finger.
 *
 * <p>The domain is compared in two parts: its first label ({@code gmial}) and the rest
 * ({@code con}). A provider is a match when the two distances together stay within what its name
 * tolerates: one edit for a four-letter name ({@code mail}, {@code live}), two for longer ones
 * ({@code gmail}, {@code hotmail}), and never more than one in the suffix. Names shorter than four
 * letters ({@code aol}, {@code gmx}, {@code me}) are accepted but never suggested: one edit away
 * from them lie too many unrelated domains.
 */
public final class MistypedEmailDomains {

    /** The providers people actually type, most used first: on a tie, the first one wins. */
    private static final List<String> PROVIDERS = List.of(
            "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "icloud.com", "live.com",
            "hotmail.es", "outlook.es", "yahoo.es", "msn.com", "ymail.com", "googlemail.com",
            "mail.com", "email.com", "me.com", "mac.com", "aol.com", "gmx.com", "gmx.net",
            "protonmail.com", "proton.me", "yandex.com", "zoho.com",
            "une.net.co", "etb.net.co", "sena.edu.co", "misena.edu.co", "soy.sena.edu.co");

    private static final int SHORTEST_SUGGESTED_NAME = 4;
    private static final int LONG_NAME = 5;

    private MistypedEmailDomains() {
    }

    /**
     * @param domain the part of the address after {@code @}
     * @return the provider the person most likely meant, or empty when the domain is a provider
     *         itself or is not close to any of them
     */
    public static Optional<String> intendedProvider(String domain) {
        String typed = domain.trim().toLowerCase(Locale.ROOT);
        if (PROVIDERS.contains(typed)) {
            return Optional.empty();
        }
        String[] typedParts = split(typed);
        String best = null;
        int bestDistance = Integer.MAX_VALUE;
        for (String provider : PROVIDERS) {
            String[] parts = split(provider);
            if (parts[0].length() < SHORTEST_SUGGESTED_NAME) {
                continue;
            }
            int suffix = distance(typedParts[1], parts[1]);
            if (suffix > 1) {
                continue;
            }
            int total = distance(typedParts[0], parts[0]) + suffix;
            int tolerated = parts[0].length() >= LONG_NAME ? 2 : 1;
            if (total <= tolerated && total < bestDistance) {
                best = provider;
                bestDistance = total;
            }
        }
        return Optional.ofNullable(best);
    }

    /** {@code gmail.com} -> {@code [gmail, com]}; a domain without a dot has an empty suffix. */
    private static String[] split(String domain) {
        int dot = domain.indexOf('.');
        return dot < 0 ? new String[] {domain, ""}
                : new String[] {domain.substring(0, dot), domain.substring(dot + 1)};
    }

    /**
     * Edits between two words, counting a swap of two neighbouring letters ({@code gmial}) as one,
     * since that is the commonest slip on a keyboard (optimal string alignment distance).
     */
    static int distance(String a, String b) {
        int[][] d = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) {
            d[i][0] = i;
        }
        for (int j = 0; j <= b.length(); j++) {
            d[0][j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                d[i][j] = Math.min(Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1), d[i - 1][j - 1] + cost);
                if (i > 1 && j > 1 && a.charAt(i - 1) == b.charAt(j - 2)
                        && a.charAt(i - 2) == b.charAt(j - 1)) {
                    d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
                }
            }
        }
        return d[a.length()][b.length()];
    }
}

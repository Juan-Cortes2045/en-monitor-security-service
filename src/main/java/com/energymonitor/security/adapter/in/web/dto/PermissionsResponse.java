package com.energymonitor.security.adapter.in.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * The permission codes the authenticated caller currently holds.
 *
 * <p><strong>Why a list of codes in one call, and not a per-code yes/no.</strong> A client needs
 * the whole set once: it builds a menu, a route guard and a set of enabled buttons from it, and it
 * only has the access token, not the catalogue of permission codes the server knows. Asking
 * {@code ?code=…} once per code would mean one round trip per candidate, a hardcoded catalogue in
 * the client to know what to ask for, and no way to render "what can this account do" at all.
 * The codes are returned instead of identifiers because the code is the stable contract (INV-022):
 * the client compares it against the strings in its own source, and it must keep working when the
 * {@code permission} table is reseeded.
 *
 * <p>The field is wrapped in an object rather than returned as a bare JSON array so the response
 * can grow without breaking clients: adding a field later (roles, an expiry, a total) is
 * compatible, whereas extending a bare array is not. It also keeps every response of this API an
 * object, like {@link AccountResponse} and {@link LoginResponse}.
 *
 * <p>The list is sorted and free of duplicates so two identical calls produce byte-identical
 * bodies, which is what lets a client diff or cache them.
 *
 * @param permissions the granted permission codes, possibly empty
 */
@Schema(name = "PermissionsResponse",
        description = "The permission codes the authenticated caller holds.")
public record PermissionsResponse(
        @Schema(description = "Stable permission codes granted through the caller's enabled "
                + "roles, sorted and without duplicates. Empty when the caller holds none.",
                example = "[\"ALERT.READ\",\"METER.READ\"]",
                requiredMode = Schema.RequiredMode.REQUIRED)
        List<String> permissions) {

    /**
     * Wraps the codes resolved by the use case.
     *
     * <p>The list is copied and made unmodifiable, so a response cannot be reshaped after the
     * controller hands it over.
     *
     * @param codes the granted codes
     * @return the response body
     */
    public static PermissionsResponse of(List<String> codes) {
        return new PermissionsResponse(List.copyOf(codes));
    }
}

package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

/**
 * Body of a profile update.
 *
 * <p>Every field is optional and absent means unchanged, so a client sends only what it wants to
 * edit. The sizes mirror the columns these values land in - {@code person.name} and
 * {@code person.last_name} are {@code VARCHAR(100)}, {@code user.email} is {@code VARCHAR(255)}
 * and {@code user.profile_image} is {@code MEDIUMTEXT} - so a value that could not be stored is rejected here, before a use
 * case runs, rather than by the database afterwards.
 *
 * <p>{@code newEmail} is not the account's current address: it is the address the caller wants
 * to move to, and it is named apart from {@code email} so that nothing in this body can be
 * mistaken for a credential or be re-used as one. Changing it resets email verification, so a
 * client must expect to confirm the new address before treating it as usable.
 *
 * <p><strong>Why the name is a pair.</strong> A person is required to have both a first name and
 * a last name (INV-001), and the aggregate replaces them together. Sending one of the two
 * therefore leaves both of them as they were, which is why the endpoint documents "both or
 * neither" rather than advertising two independently editable fields it cannot honour.
 *
 * <p><strong>There is no phone number here.</strong> The field existed once and was removed from
 * the domain, from the {@code person} table and from the registration body before this endpoint
 * existed, because notifications are delivered by email only and a contact channel nothing
 * delivers to has no reason to be stored against a person. A client still sending {@code phone}
 * is not broken: the property is unknown here and is ignored, so old clients keep working while
 * the server stores nothing. Adding the field back would mean re-adding the column, and this
 * record is deliberately shaped so that doing so cannot happen by accident.
 *
 * @param name         new first name, {@code null} to keep
 * @param lastName     new last name, {@code null} to keep
 * @param profileImage new avatar (URL or data URL), blank to remove it, {@code null} to keep
 * @param newEmail     address to move the account to, {@code null} to keep
 */
public record UpdateProfileRequest(
        @Size(max = 100) String name,
        @Size(max = 100) String lastName,
        @Size(max = 500_000) String profileImage,
        @Email @Size(max = 255) String newEmail) {
}
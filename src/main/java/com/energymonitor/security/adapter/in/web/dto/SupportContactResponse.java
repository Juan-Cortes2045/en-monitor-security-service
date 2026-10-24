package com.energymonitor.security.adapter.in.web.dto;

/**
 * An administrator the public support page can write to.
 *
 * @param name  first and last name, as the person sees them in the list
 * @param email the address the message goes to
 */
public record SupportContactResponse(String name, String email) {
}

package com.energymonitor.security.adapter.in.web.dto;

/**
 * Acknowledgement for endpoints with nothing to return.
 *
 * @param message a caller-safe description of what happened
 */
public record MessageResponse(String message) {
}

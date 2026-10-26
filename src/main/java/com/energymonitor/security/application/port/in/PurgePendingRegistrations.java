package com.energymonitor.security.application.port.in;

/** Removes the registrations whose verification code never came back in time. */
public interface PurgePendingRegistrations {

    /** @return how many registrations were removed */
    int purgeExpired();
}

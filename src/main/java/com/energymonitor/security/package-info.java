/**
 * Security service: the Security bounded context of EnergyMonitor, deployed on its own.
 *
 * <p>Owns identity, authentication, sessions, RBAC and the audit trail. Upstream of every other
 * service: the rest of the system reads the caller's identity from the access token claims, which
 * only this service signs. What other services may ask it (profiles, administrators, permissions)
 * and what it announces to them (account events) are the contracts in {@code api}.
 *
 * <p>Internal layout: {@code domain}, {@code application}, {@code adapter},
 * {@code infrastructure}.
 */
package com.energymonitor.security;

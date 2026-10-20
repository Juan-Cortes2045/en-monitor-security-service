/**
 * Public contracts of the security service.
 *
 * <p>It holds what other services are meant to receive or ask for, and nothing else: the account
 * events, the profile and administrator queries, and the mail delivery requests. The output ports
 * that only this service implements stay in {@code application.port.out}.
 */
package com.energymonitor.security.api;

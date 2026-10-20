package com.energymonitor.security.application.port.out;

import java.util.Optional;

/**
 * Downloads a remote profile photo and returns it the way the account stores an uploaded one.
 */
public interface ProfileImageFetcherPort {

    /** @return a {@code data:image/...;base64,...} URL, empty on any failure */
    Optional<String> fetchAsDataUrl(String url);
}

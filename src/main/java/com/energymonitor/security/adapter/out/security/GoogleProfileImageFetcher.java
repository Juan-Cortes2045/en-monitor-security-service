package com.energymonitor.security.adapter.out.security;

import com.energymonitor.security.application.port.out.ProfileImageFetcherPort;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Downloads the Google profile photo and stores it as a data URL, like an uploaded avatar:
 * Google photo addresses change over time, a stored copy does not.
 *
 * <p>Only {@code https} addresses of {@code googleusercontent.com} are fetched, so the server can
 * never be pointed at an arbitrary address. The photo is asked at 256 px and capped at 300 KB.
 */
@Component
public class GoogleProfileImageFetcher implements ProfileImageFetcherPort {

    private static final Logger LOG = LoggerFactory.getLogger(GoogleProfileImageFetcher.class);
    private static final int MAX_BYTES = 300_000;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @Override
    public Optional<String> fetchAsDataUrl(String url) {
        try {
            URI uri = URI.create(sized(url));
            String host = uri.getHost();
            if (!"https".equals(uri.getScheme()) || host == null
                    || !(host.equals("googleusercontent.com") || host.endsWith(".googleusercontent.com"))) {
                return Optional.empty();
            }
            HttpResponse<byte[]> response = http.send(HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofByteArray());
            String type = response.headers().firstValue("Content-Type").orElse("");
            byte[] body = response.body();
            if (response.statusCode() != 200 || !type.startsWith("image/") || body.length == 0
                    || body.length > MAX_BYTES) {
                return Optional.empty();
            }
            String mime = type.split(";")[0].trim();
            return Optional.of("data:" + mime + ";base64," + Base64.getEncoder().encodeToString(body));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (Exception e) {
            LOG.info("Google profile photo could not be downloaded: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /** Google photo URLs end in "=s96-c" (size); ask for 256 px. */
    static String sized(String url) {
        return url.replaceFirst("=s\\d+(-c)?$", "=s256-c");
    }
}

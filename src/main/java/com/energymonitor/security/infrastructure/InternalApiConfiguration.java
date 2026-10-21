package com.energymonitor.security.infrastructure;

import com.energymonitor.security.adapter.out.backend.HttpAccountDeletionGuard;
import com.energymonitor.security.application.port.out.AccountDeletionGuardPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestClient;

/**
 * The calls between this service and energy-monitor-backend, both ways.
 *
 * <p>Inbound, {@code /internal/**} gets its own filter chain, evaluated before the API chain: the
 * backend presents no JWT, so it is trusted by network and shared token instead (see
 * {@link InternalCallerCheck}). Anything else is answered 403. The reverse proxy must not forward
 * {@code /internal/**} at all, since behind it every request seems to come from the proxy.
 *
 * <p>Outbound, the client that asks the backend whether an account may be deleted.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(InternalApiProperties.class)
public class InternalApiConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(InternalApiConfiguration.class);

    @Bean
    @Order(1)
    public SecurityFilterChain internalApiFilterChain(HttpSecurity http,
                                                      InternalApiProperties properties)
            throws Exception {
        if (properties.token() == null || properties.token().isBlank()) {
            LOG.warn("internal-api.token is empty: every call to /internal/** will be refused");
        }
        InternalCallerCheck callers = new InternalCallerCheck(properties);
        return http
                .securityMatcher("/internal/**")
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                        .anyRequest().access((authentication, context) ->
                                new AuthorizationDecision(callers.trusts(context.getRequest()))))
                .build();
    }

    @Bean
    public AccountDeletionGuardPort accountDeletionGuard(InternalApiProperties properties) {
        SimpleClientHttpRequestFactory requests = new SimpleClientHttpRequestFactory();
        requests.setConnectTimeout(properties.connectTimeout());
        requests.setReadTimeout(properties.readTimeout());
        RestClient client = RestClient.builder()
                .baseUrl(properties.backendUrl().toString())
                .requestFactory(requests)
                .defaultHeader(InternalApiProperties.TOKEN_HEADER,
                        properties.token() == null ? "" : properties.token())
                .build();
        return new HttpAccountDeletionGuard(client);
    }
}

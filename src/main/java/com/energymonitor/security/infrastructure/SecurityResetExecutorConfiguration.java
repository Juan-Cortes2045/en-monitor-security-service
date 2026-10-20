package com.energymonitor.security.infrastructure;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The queue that password-recovery requests are processed on.
 *
 * <p>It lives here, in security, and not in the module that eventually sends the mail, because what
 * it protects is a property of the endpoint: every request to {@code /password/forgot} gets the same
 * answer, whether or not the account exists. That answer is sent before the request is processed, so
 * a caller learns nothing from how long it took, and the work that could otherwise leak that
 * difference happens here instead of on the request thread.
 *
 * <p>The shape is deliberately the one already proven: a fixed number of workers on a bounded
 * {@link ArrayBlockingQueue}, daemon threads, and {@link ThreadPoolExecutor.AbortPolicy}. What is
 * deliberately absent is {@code CallerRunsPolicy}, which would run the work on the request thread,
 * which is the single thing this queue exists to prevent, and would turn a full queue into exactly
 * the latency the queue was added to remove.
 *
 * <p>Aborting is not a failure mode here. {@code AuthController} catches the rejection and still
 * answers 202, because a full queue must not become a way to tell a registered address from an
 * unregistered one either.
 *
 * <p>Daemon threads, so a shutdown is never held open by a queue of pending requests.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecurityResetExecutorProperties.class)
public class SecurityResetExecutorConfiguration {

    /**
     * The pool recovery requests run on.
     *
     * @param properties queue size and thread count
     * @return the executor, named so the controller can inject exactly this one
     */
    @Bean(name = "passwordResetExecutor", destroyMethod = "shutdown")
    public ThreadPoolExecutor passwordResetExecutor(SecurityResetExecutorProperties properties) {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                properties.workerThreads(),
                properties.workerThreads(),
                0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(properties.queueCapacity()),
                runnable -> {
                    Thread worker = new Thread(runnable, "password-reset");
                    worker.setDaemon(true);
                    return worker;
                },
                new ThreadPoolExecutor.AbortPolicy());
        executor.allowCoreThreadTimeOut(false);
        return executor;
    }
}
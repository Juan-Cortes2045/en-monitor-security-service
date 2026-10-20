package com.energymonitor.security.infrastructure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Queue settings for password-recovery dispatch, bound from {@code security.reset.executor.*}.
 *
 * <p>Separate from {@link SecurityResetProperties} on purpose. That record describes how hard a code
 * is to guess; this one describes how many recovery requests may be in flight. They change for
 * different reasons and are tuned by different people, and folding queue sizing into the record
 * that guards the pepper would let a deployment shorten a window without noticing what else moved
 * with it.
 *
 * @param workerThreads requests processed at once
 * @param queueCapacity requests allowed to wait before new ones are refused
 */
@ConfigurationProperties(prefix = "security.reset.executor")
public record SecurityResetExecutorProperties(Integer workerThreads, Integer queueCapacity) {

    /** Requests processed at once. Two is a number, not a preference: it is what was measured. */
    public static final int DEFAULT_WORKER_THREADS = 2;

    /**
     * Requests allowed to wait.
     *
     * <p>Bounded because an unbounded queue converts a slow dependency into memory pressure behind
     * an endpoint that keeps answering 202.
     */
    public static final int DEFAULT_QUEUE_CAPACITY = 100;

    public SecurityResetExecutorProperties {
        workerThreads = workerThreads == null ? DEFAULT_WORKER_THREADS : workerThreads;
        queueCapacity = queueCapacity == null ? DEFAULT_QUEUE_CAPACITY : queueCapacity;
    }
}
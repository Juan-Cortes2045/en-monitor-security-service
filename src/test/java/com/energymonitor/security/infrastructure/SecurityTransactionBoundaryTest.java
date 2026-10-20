package com.energymonitor.security.infrastructure;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.port.in.AssignRole;
import com.energymonitor.security.application.port.in.AuthenticateUser;
import com.energymonitor.security.application.port.in.ChangePassword;
import com.energymonitor.security.application.port.in.CheckPermission;
import com.energymonitor.security.application.port.in.CreatePasswordResetToken;
import com.energymonitor.security.application.port.in.CreateUserSession;
import com.energymonitor.security.application.port.in.FindUser;
import com.energymonitor.security.application.port.in.LogoutUserSession;
import com.energymonitor.security.application.port.in.ManageUserStatus;
import com.energymonitor.security.application.port.in.RegisterUser;
import com.energymonitor.security.application.port.in.ResetPassword;
import com.energymonitor.security.application.port.in.RevokeRole;
import com.energymonitor.security.application.port.in.UpdateUserProfile;
import java.util.List;
import org.aopalliance.aop.Advice;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.interceptor.TransactionInterceptor;

/**
 * Where the transaction boundary sits, and that Spring actually honours it.
 *
 * <p>Declaring {@code @Transactional} is only half the job: if the use case bean is not
 * wrapped in a proxy the annotation is inert and a multi-write flow can leave half its rows
 * behind. These tests therefore check the runtime shape of the bean, not just the source
 * annotation, and they pin the deliberate omission on the single-write and read-only flows so
 * a later change cannot quietly add a transaction where there is nothing to make atomic.
 *
 * <p><strong>One flow moved to the transactional side, on purpose.</strong> Issuing a recovery
 * code used to be asserted here as a single-write flow with no boundary, on the reasoning that a
 * transaction cannot un-send a message. That was true while the mail left inside the call. Delivery
 * is now queued and dispatched after the commit, so the boundary is what makes the ordering
 * honest: without it the callback has no commit to wait for and the message would be built against
 * a row a later failure could still remove. {@link #createPasswordResetTokenIsTransactionalBecauseItsDeliveryWaitsForTheCommit()}
 * states the new invariant so the change cannot be reversed by accident.
 */
@SpringBootTest
class SecurityTransactionBoundaryTest extends JwtKeyedTest {

    @Autowired
    private RegisterUser registerUser;

    @Autowired
    private AuthenticateUser authenticateUser;

    @Autowired
    private UpdateUserProfile updateUserProfile;

    @Autowired
    private ManageUserStatus manageUserStatus;

    @Autowired
    private ChangePassword changePassword;

    @Autowired
    private ResetPassword resetPassword;

    @Autowired
    private LogoutUserSession revokeUserSession;

    @Autowired
    private AssignRole assignRole;

    @Autowired
    private RevokeRole revokeRole;

    @Autowired
    private CreatePasswordResetToken createPasswordResetToken;

    @Autowired
    private CreateUserSession createUserSession;

    @Autowired
    private FindUser findUser;

    @Autowired
    private CheckPermission checkPermission;

    /**
     * Flows that write more than one row, or write a row and an audit record. A partial commit
     * would leave a counter, an audit trail or an assignment inconsistent with the row it
     * describes, so each one gets its own transaction.
     */
    private List<Object> multiWriteFlows() {
        return List.of(registerUser, authenticateUser, updateUserProfile, manageUserStatus,
                changePassword, resetPassword, revokeUserSession, assignRole, revokeRole);
    }

    private List<Class<?>> advisedTypes(Object bean) {
        List<Class<?>> types = new java.util.ArrayList<>();
        for (org.springframework.aop.Advisor advisor : ((Advised) bean).getAdvisors()) {
            Advice advice = advisor.getAdvice();
            types.add(advice == null ? Object.class : advice.getClass());
        }
        return types;
    }

    private void assertRunsInATransaction(Object bean) {
        assertTrue(AopUtils.isAopProxy(bean),
                bean.getClass() + " is not proxied, so @Transactional would be inert");
        boolean transactional = advisedTypes(bean).contains(TransactionInterceptor.class);
        assertTrue(transactional, bean.getClass() + " has no transaction advisor");
    }

    private void assertHasNoBoundary(Object bean) {
        boolean transactional = AopUtils.isAopProxy(bean)
                && advisedTypes(bean).contains(TransactionInterceptor.class);
        assertFalse(transactional,
                bean.getClass() + " was given a transaction although it writes a single row"
                        + " or reads only");
    }

    @Test
    void everyMultiWriteFlowRunsBehindATransactionProxy() {
        multiWriteFlows().forEach(this::assertRunsInATransaction);
    }

    @Test
    void theTransactionAdviceIsSpringOwnRatherThanACustomOne() {
        for (Object bean : multiWriteFlows()) {
            assertTrue(advisedTypes(bean).contains(TransactionInterceptor.class),
                    bean.getClass() + " is not advised by the Spring transaction interceptor");
        }
    }

    @Test
    void theSingleWriteFlowsCarryNoTransactionBoundary() {
        assertHasNoBoundary(createUserSession);
    }

    @Test
    void createPasswordResetTokenIsTransactionalBecauseItsDeliveryWaitsForTheCommit() {
        // A recovery code row and a message that quotes it have to agree: if the send were dispatched
        // before the commit and the transaction then failed, the recipient would hold a code that does
        // not exist. The boundary is what orders them, so this one single-write flow has one.
        assertRunsInATransaction(createPasswordResetToken);
    }

    @Test
    void theReadOnlyFlowsCarryNoTransactionBoundary() {
        assertHasNoBoundary(findUser);
        assertHasNoBoundary(checkPermission);
    }
}

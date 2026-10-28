package com.energymonitor.security.adapter.in.web.internal;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.energymonitor.security.api.AdministratorQuery;
import com.energymonitor.security.api.UserProfile;
import com.energymonitor.security.api.UserProfileQuery;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.CheckPermission;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The internal routes energy-monitor-backend calls: who may reach them, and what they answer.
 * The token is the one of the test profile; MockMvc requests come from 127.0.0.1.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Internal API")
class InternalControllerWebTest extends JwtKeyedTest {

    private static final String TOKEN = "test-only-internal-token";

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private CheckPermission checkPermission;

    @MockitoBean
    private UserProfileQuery profiles;

    @MockitoBean
    private AdministratorQuery administrators;

    @Test
    @DisplayName("without the token the call is refused")
    void withoutToken() throws Exception {
        mvc.perform(get("/internal/administrators")).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("with a wrong token the call is refused")
    void wrongToken() throws Exception {
        mvc.perform(get("/internal/administrators").header("X-Internal-Token", "guess"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("the right token from outside the allowed networks is refused")
    void outsideNetwork() throws Exception {
        mvc.perform(get("/internal/administrators").header("X-Internal-Token", TOKEN)
                        .with(request -> {
                            request.setRemoteAddr("203.0.113.7");
                            return request;
                        }))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a user's JWT does not open the internal routes")
    void bearerIsNotEnough() throws Exception {
        mvc.perform(get("/internal/administrators").header("Authorization", "Bearer anything"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("lists the administrators")
    void administrators() throws Exception {
        given(administrators.activeAdministratorIds()).willReturn(List.of("use0000001"));

        mvc.perform(get("/internal/administrators").header("X-Internal-Token", TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userIds[0]").value("use0000001"));
    }

    @Test
    @DisplayName("lists the permission codes of an account")
    void permissions() throws Exception {
        given(checkPermission.listGrantedCodes("use0000001")).willReturn(List.of("USER.READ"));

        mvc.perform(get("/internal/users/use0000001/permissions").header("X-Internal-Token", TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions[0]").value("USER.READ"));
    }

    @Test
    @DisplayName("an unknown account has no permissions to list")
    void unknownAccount() throws Exception {
        given(checkPermission.listGrantedCodes("use0000404"))
                .willThrow(new UserNotFoundException("no active user use0000404"));

        mvc.perform(get("/internal/users/use0000404/permissions").header("X-Internal-Token", TOKEN))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("looks up profiles in one call")
    void profiles() throws Exception {
        given(profiles.findByIds(List.of("use0000001", "use0000404"))).willReturn(Map.of(
                "use0000001", new UserProfile("use0000001", "Ada", "Lovelace", "ada@example.com", null)));

        mvc.perform(post("/internal/users/profiles").header("X-Internal-Token", TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userIds\":[\"use0000001\",\"use0000404\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.profiles.length()").value(1))
                .andExpect(jsonPath("$.profiles[0].name").value("Ada"))
                .andExpect(jsonPath("$.profiles[0].email").value("ada@example.com"));
    }

    @Test
    @DisplayName("a profile lookup without the list is a bad request")
    void profilesWithoutList() throws Exception {
        mvc.perform(post("/internal/users/profiles").header("X-Internal-Token", TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }
}

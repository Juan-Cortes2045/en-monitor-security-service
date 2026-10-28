package com.energymonitor.security.adapter.in.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.energymonitor.security.api.AdministratorQuery;
import com.energymonitor.security.api.UserProfile;
import com.energymonitor.security.api.UserProfileQuery;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/** The public support page learns who it can write to: the active administrators. */
@SpringBootTest
@AutoConfigureMockMvc
class SupportControllerWebTest extends JwtKeyedTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private AdministratorQuery administrators;

    @MockitoBean
    private UserProfileQuery profiles;

    @Test
    void listsTheActiveAdministratorsByNameWithoutAToken() throws Exception {
        given(administrators.activeAdministratorIds()).willReturn(List.of("adm0000002", "adm0000001"));
        given(profiles.findByIds(any())).willReturn(Map.of(
                "adm0000002", new UserProfile("adm0000002", "Sofía", "Ríos", "sofia@energymonitor.co", null),
                "adm0000001", new UserProfile("adm0000001", "Andrés", "Gil", "andres@energymonitor.co", null)));

        mvc.perform(get("/api/v1/support/contacts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].name").value("Andrés Gil"))
                .andExpect(jsonPath("$[0].email").value("andres@energymonitor.co"))
                .andExpect(jsonPath("$[1].name").value("Sofía Ríos"))
                .andExpect(jsonPath("$[0].idUser").doesNotExist());
    }

    @Test
    void usesTheAddressWhenAnAdministratorHasNoName() throws Exception {
        given(administrators.activeAdministratorIds()).willReturn(List.of("adm0000001"));
        given(profiles.findByIds(any())).willReturn(Map.of(
                "adm0000001", new UserProfile("adm0000001", " ", null, "soporte@energymonitor.co", null)));

        mvc.perform(get("/api/v1/support/contacts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").value("soporte@energymonitor.co"));
    }

    @Test
    void answersAnEmptyListWhenThereIsNoAdministrator() throws Exception {
        given(administrators.activeAdministratorIds()).willReturn(List.of());
        given(profiles.findByIds(any())).willReturn(Map.of());

        mvc.perform(get("/api/v1/support/contacts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }
}

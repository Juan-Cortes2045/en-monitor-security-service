package com.energymonitor.security.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.energymonitor.security.api.UserProfile;
import com.energymonitor.security.application.usecase.UserProfileQueryService;
import com.energymonitor.security.domain.model.UserStatus;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class UserProfileQueryServiceTest {

    private final UseCaseFixtures.FakeUserPersistencePort users =
            new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakePersonPersistencePort persons =
            new UseCaseFixtures.FakePersonPersistencePort();
    private final UserProfileQueryService profiles = new UserProfileQueryService(users, persons);

    @Test
    @DisplayName("resolves each known account to its person's name and the account's address")
    void resolvesKnownAccounts() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        persons.seed("per0000001");

        var found = profiles.findByIds(Arrays.asList("use0000001", "use0000001", "use0000099", null));

        assertThat(found).containsOnlyKeys("use0000001");
        assertThat(found.get("use0000001"))
                .isEqualTo(new UserProfile("use0000001", "Ada", "Lovelace", "ada@example.com", null));
    }

    @Test
    @DisplayName("includes the avatar the person chose, and none when there is no avatar")
    void includesTheAvatar() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE)
                .changeProfileImage("data:image/png;base64,AAAA");
        users.seed("use0000002", "per0000002", "bob@example.com", UserStatus.ACTIVE);
        persons.seed("per0000001");
        persons.seed("per0000002");

        var found = profiles.findByIds(Arrays.asList("use0000001", "use0000002"));

        assertThat(found.get("use0000001").profileImage()).isEqualTo("data:image/png;base64,AAAA");
        assertThat(found.get("use0000002").profileImage()).isNull();
    }
}

package io.pivotal.security.controller.v1.health;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class HealthControllerTest {

  @Autowired
  protected ConfigurableWebApplicationContext context;

  @Autowired
  private HealthController subject;

  @MockBean
  private DataSourceHealthIndicator dataSourceHealthIndicator;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
    });

    it("can answer that we're unhealthy", () -> {
      doAnswer((invocation) -> {
        invocation.getArgumentAt(0, Health.Builder.class).down(new RuntimeException("some error"));
        return null; })
          .when(dataSourceHealthIndicator).checkHealth(any(Health.Builder.class));

      mockMvc.perform(get("/health"))
          .andExpect(status().isOk())
          .andExpect(content().json("{\"db\": {\"status\":\"DOWN\",\"error\":\"java.lang.RuntimeException: some error\"}}"));
    });

    it("can answer that we're healthy", () -> {
      doAnswer((invocation) -> {
        invocation.getArgumentAt(0, Health.Builder.class).up();
        return null; })
          .when(dataSourceHealthIndicator).checkHealth(any(Health.Builder.class));

      mockMvc.perform(get("/health"))
          .andExpect(status().isOk())
          .andExpect(content().json("{\"db\": {\"status\":\"UP\"}}"));
    });
  }
}

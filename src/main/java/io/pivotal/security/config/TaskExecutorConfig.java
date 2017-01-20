package io.pivotal.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.scheduling.annotation.AsyncConfigurerSupport;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.concurrent.Executor;

@Configuration
@EnableAsync
public class TaskExecutorConfig extends AsyncConfigurerSupport {

  @Override
  public Executor getAsyncExecutor() {
    return new SimpleAsyncTaskExecutor();
  }
}

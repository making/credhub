package io.pivotal.security.mapper;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.Option;
import io.pivotal.security.util.StringUtil;
import io.pivotal.security.view.ParameterizedValidationException;

import static com.google.common.collect.Lists.newArrayList;
import static com.jayway.jsonpath.JsonPath.using;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public interface RequestTranslator<ET> {
  void populateEntityFromJson(ET namedSecret, DocumentContext documentContext);

  Set<String> getValidKeys();

  default void validateJsonKeys(DocumentContext parsed) {
    Set<String> keys = getValidKeys();
    Configuration conf = Configuration.builder().options(Option.AS_PATH_LIST).build();
    List<String> pathList = using(conf).parse(parsed.jsonString()).read("$..*");
    pathList = pathList.stream().map(StringUtil::convertJsonArrayRefToWildcard).collect(Collectors.toList());
    pathList.removeAll(keys);
    if (pathList.size() > 0) {
      throw new ParameterizedValidationException("error.invalid_json_key", newArrayList(pathList.get(0)));
    }
  }

  default void validatePathName(String name) {
    if (name.contains("//") || name.endsWith("/")) {
      throw new ParameterizedValidationException("error.invalid_name_has_slash");
    }
  }
}

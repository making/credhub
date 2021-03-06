package io.pivotal.security.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.isEmpty;

public class StringUtil {

  public static final String INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS = "[*]";
  private static Pattern JSON_ARRAY_REF = Pattern.compile("(.*)\\[\\d+\\](.*)");

  public static String convertJsonArrayRefToWildcard(String jsonPath) {
    String result = jsonPath;
    Matcher matcher = JSON_ARRAY_REF.matcher(jsonPath);
    if (matcher.matches()) {
      result = matcher.group(1) + INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS + matcher.group(2);
    }
    return result;
  }

  public static String emptyToNull(String val) {
    return isEmpty(val) ? null : val;
  }

  public static boolean isBlank(String caName) {
    return caName == null || caName.isEmpty();
  }
}

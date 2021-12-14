package com.stripe.log4j.isitvuln;

import java.util.Arrays;
import java.util.List;

public class FileFormats {
  public static final List<String> SYSPROPS_FOR_CSV = Arrays.asList(
      "log4j2.formatMsgNoLookups",
      "com.sun.jndi.rmi.object.trustURLCodebase",
      "com.sun.jndi.cosnaming.object.trustURLCodebase",
      "com.sun.jndi.ldap.object.trustURLCodebase");

  public static String toCsv(String... cells) {
    StringBuilder sb = new StringBuilder();
    boolean first = true;
    for (String cell : cells) {
      if (!first) {
        sb.append(',');
      }
      first = false;
      sb.append(escapeSpecialCharacters(cell));
    }
    return sb.toString();
  }

  public static String escapeSpecialCharacters(String data) {
    if (data == null) {
      return "null";
    }
    String escapedData = data.replaceAll("\\R", " ");
    if (data.contains(",") || data.contains("\"") || data.contains("'")) {
      data = data.replace("\"", "\"\"");
      escapedData = "\"" + data + "\"";
    }
    return escapedData;
  }
}

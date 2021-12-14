package com.stripe.log4j.isitvuln;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class HostInfo {
  public static final String HOSTNAME = getHostname();

  private static String getHostname() {
    InetAddress localHost;
    try {
      localHost = InetAddress.getLocalHost();
    } catch (Exception e) {
      System.err.println("Could not get local host address");
      e.printStackTrace();
      return "unknown";
    }
    try {
      return localHost.getHostName();
    } catch (Exception e) {
      System.err.println("Could not get local host name");
      e.printStackTrace();
      return localHost.toString();
    }
  }
}

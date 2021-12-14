package com.stripe.log4j.isitvuln;

import sun.management.VMManagement;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URISyntaxException;

public class ProcessInfo {
  public static final String THIS_JAR_PATH = getThisJarPath();
  public static final int MY_PID = getMyPidNoThrow();

  public static String getThisJarPath() {
    try {
      return IsItVuln.class.getProtectionDomain().getCodeSource().getLocation()
          .toURI().getPath();
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  private static int getMyPidNoThrow() {
    int pid = -1;
    try {
      pid = getMyPid();
    } catch (Exception e) {
      System.err.println("WARN: could not get my pid");
      e.printStackTrace();
    }
    return pid;
  }

  private static int getMyPid() throws Exception {

    RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
    Field jvm = runtime.getClass().getDeclaredField("jvm");
    jvm.setAccessible(true);

    VMManagement management = (VMManagement) jvm.get(runtime);
    Method method = management.getClass().getDeclaredMethod("getProcessId");
    method.setAccessible(true);

    return (Integer) method.invoke(management);
  }
}

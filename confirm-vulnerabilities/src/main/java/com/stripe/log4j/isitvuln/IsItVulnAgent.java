package com.stripe.log4j.isitvuln;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

public class IsItVulnAgent {
  private final static AtomicInteger runs = new AtomicInteger(0);

  public static void agentmain(String agentArgs, Instrumentation inst) throws Throwable {
    try {
      String[] args = agentArgs.split(" ");
      String version = args[0];

      if (!version.equals(IsItVuln.VERSION_NUMBER)) {
        throw new IllegalStateException(
            String.format(
                "agent is running old version of code and force reloading classes is not implemented (tool version %s != agent version %s)",
                version, IsItVuln.VERSION_NUMBER));
      }
      int previousRuns = runs.getAndIncrement();
      if (previousRuns != 0) {
        System.err.printf(
            "WARN: this is IsItVuln agent run #%d without reloading classes, though we appear to be on the right version (%s)%n",
            previousRuns + 1, version);
      }

      int port = Integer.parseInt(args[1]);
      String outputFile = args[2];

      writePropertiesFile(outputFile, populateProperties(inst, port));
    } catch (Throwable e) {
      System.err.println("IsItVuln agent failed");
      e.printStackTrace();
      throw e;
    }
  }

  private static Properties populateProperties(Instrumentation inst, int port) {
    Properties result = new Properties();

    checkLog4j(inst, port, result);

    for (String name : FileFormats.SYSPROPS_FOR_CSV) {
      result.put(name, System.getProperty(name, "unset"));
    }
    return result;
  }

  private static void writePropertiesFile(String outputFile, Properties result) throws IOException {
    String tmpFile = outputFile + ".tmp";
    try (PrintWriter out = new PrintWriter(new FileWriter(tmpFile))) {
      result.store(out, null);
    }
    Files.move(Paths.get(tmpFile), Paths.get(outputFile), ATOMIC_MOVE, REPLACE_EXISTING);
  }

  private static void checkLog4j(Instrumentation inst, int port, Properties result) {
    result.put("log4j", "none");
    result.put("hasLog4j", "false");
    for (Class<?> cls : inst.getAllLoadedClasses()) {
      if (cls.getName().equals("org.apache.logging.log4j.Logger")) {
        String ver = cls.getPackage().getImplementationVersion();
        if (!result.containsKey("log4j") || result.getProperty("log4j").equals("unknown")) {
          result.put("log4j", ver != null ? ver : "unknown");
        }
        result.put("hasLog4j", "true");
      } else if (cls.getName().equals("org.apache.logging.log4j.LogManager")) {
        tryLoggingExploitString(cls, port);
      }
    }
  }

  private static void tryLoggingExploitString(Class<?> cls, int port) {
    try {
      Object logger = cls.getMethod("getLogger", Class.class).invoke(null, IsItVulnAgent.class);
      Method errorMethod = logger.getClass().getMethod("error", String.class);
      String logLine = String.format("IsItVuln ExploitAttempt ${jndi:ldap://127.0.0.1:%d/x}", port);
      System.err.println("Attempting to log " + logLine);
      errorMethod.invoke(logger, logLine);
    } catch (Exception e) {
      e.printStackTrace();
      //TODO: log this error to file
    }
    //TODO: serious failure if that didn't work!
  }
}

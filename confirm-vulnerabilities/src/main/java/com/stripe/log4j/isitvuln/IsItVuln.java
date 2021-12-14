package com.stripe.log4j.isitvuln;

import sun.jvmstat.monitor.MonitoredHost;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class IsItVuln {

  public static final String VERSION_NUMBER = "1";

  private static final int TIMEOUT_SECS = 60;

  public static void main(String[] args) throws InterruptedException {
    System.err.println("Will use this jar for agent: " + ProcessInfo.THIS_JAR_PATH);
    Path temp = createTempDir();

    ExecutorService inspectionThreads = Executors.newCachedThreadPool();

    printAtomic("date,host,tool,version,pid,path,jre,log4j,log4j version,formatMsgNoLookups,ldap trustURLCodebase,rmi trustURLCodebase,cosnaming trustURLCodebase,exploited");
    List<InspectedJVM> jvms = new ArrayList<>();
    try {
      MonitoredHost host = MonitoredHost.getMonitoredHost((String) null);
      for (int pid : host.activeVms()) {
        if (pid == ProcessInfo.MY_PID) {
          continue;
        }
        Path outputFile = temp.resolve("result-" + pid + ".csv");
        InspectedJVM inspectedJVM = new InspectedJVM(pid, host, outputFile, IsItVuln::printAtomic);
        jvms.add(inspectedJVM);
        inspectionThreads.submit(inspectedJVM::inspect);
      }
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }

    waitForAllVmInspectionsToComplete(jvms, inspectionThreads);
  }

  private synchronized static void printAtomic(String x) {
    System.out.println(x);
  }


  private static void waitForAllVmInspectionsToComplete(List<InspectedJVM> jvms, ExecutorService executor) throws InterruptedException {
    long startNano = System.nanoTime();
    jvms.forEach(InspectedJVM::pleaseFinish);
    executor.shutdown();
    while (!executor.isTerminated()) {
      if (TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - startNano) >= TIMEOUT_SECS) {
        System.err.println("Exiting after " + TIMEOUT_SECS + " sec timeout");
        System.exit(18);
        return;
      }
      Thread.sleep(1000);
    }
  }

  private static Path createTempDir() {
    Path path;
    try {
      path = Files.createTempDirectory("is-it-vuln").toAbsolutePath();
    } catch (IOException e) {
      System.err.println("Could not create tmpdir");
      System.exit(8);
      throw new RuntimeException(e);
    }
    return path;
  }

}

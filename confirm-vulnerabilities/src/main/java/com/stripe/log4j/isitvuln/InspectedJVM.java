package com.stripe.log4j.isitvuln;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.MonitoredVm;
import sun.jvmstat.monitor.MonitoredVmUtil;
import sun.jvmstat.monitor.VmIdentifier;

import java.io.FileReader;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static com.stripe.log4j.isitvuln.IsItVuln.VERSION_NUMBER;

class InspectedJVM {
  public static final int MIN_WAIT_SECS = 5;
  int pid;
  MonitoredHost host;
  Path output;

  String vmName;
  String vendor;
  String vmVersion;
  String args;
  String javaHome;
  Exception exception;
  String javaVersion;
  private Properties sysProps;

  int ldapServerPort = -1;
  volatile boolean gotLdapConnection = false;
  volatile boolean pleaseFinish = false;
  private final Consumer<String> print;

  InspectedJVM(int pid, MonitoredHost host, Path outputFile, Consumer<String> print) {
    this.pid = pid;
    this.host = host;
    this.output = outputFile;
    this.print = print;
  }

  public void inspect() {

    String mainClass = "unknown";
    try {
      MonitoredVm jvm = host.getMonitoredVm(new VmIdentifier(Integer.toString(pid)));
      mainClass = MonitoredVmUtil.mainClass(jvm, true);
      this.args = MonitoredVmUtil.jvmArgs(jvm);
      this.javaHome = (String) jvm.findByName("java.property.java.home").getValue();
      this.vmName = (String) jvm.findByName("java.property.java.vm.name").getValue();
      this.vendor = (String) jvm.findByName("java.property.java.vm.vendor").getValue();
      this.vmVersion = MonitoredVmUtil.vmVersion(jvm);
      this.javaVersion = (String) jvm.findByName("java.property.java.version").getValue();
      this.startServer();

      System.err.println("Attempting to attach to to " + pid + " running " + mainClass);
      VirtualMachine vm = VirtualMachine.attach(Integer.toString(pid));
      this.sysProps = vm.getSystemProperties();
      installAgent(this.output.toString(), this.ldapServerPort, vm);
    } catch (Exception e) {
      this.exception = e;
      //TODO: write this to the output csv?
      System.err.println("Failed to attach to " + pid + " running " + mainClass + ": " + e);
      e.printStackTrace();
      return;
    }

    long start = System.nanoTime();
    while (!this.output.toFile().exists() && !(pleaseFinish && secondsElapsed(start) > MIN_WAIT_SECS)) {
      try {
        Thread.sleep(1000);
      } catch (InterruptedException e) {
        e.printStackTrace();
        break;
      }
    }
    if (!this.output.toFile().exists()) {
      System.err.println("Never saw creation of " + this.output);
    }
    printCsv();
  }

  private long secondsElapsed(long nanos) {
    return TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - nanos);
  }

  private static void installAgent(String path, int port, VirtualMachine vm)
      throws IOException, AgentLoadException, AgentInitializationException {
    //TODO: how to force reload agent?
    try {
      vm.loadAgent(ProcessInfo.THIS_JAR_PATH, VERSION_NUMBER + " " + port + " " + path);
    } catch (AgentLoadException e) {
      // dunno why this exception message means success but it does
      if (!"0".equals(e.getMessage())) {
        throw e;
      }
    }
  }

  private void printCsv() {
    System.err.println("Parsing " + this.output);
    Properties propsFromAgent;
    try (FileReader reader = new FileReader(this.output.toFile())) {
      propsFromAgent = new Properties();
      propsFromAgent.load(reader);

    } catch (IOException e) {
      System.err.println("Error reading output files");
      e.printStackTrace();
      System.exit(10);
      return;
    }

    String log4jVersion = propsFromAgent.getProperty("log4j", "error");
    StringBuilder line = new StringBuilder(FileFormats.toCsv(
        ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT),
        HostInfo.HOSTNAME,
        "is-it-vuln",
        VERSION_NUMBER,
        Integer.toString(this.pid),
        this.javaHome,
        this.vendor + " - " + this.vmName + " - " + this.javaVersion,
        propsFromAgent.getProperty("hasLog4j", "maybe")
    ));
    for (String key : FileFormats.SYSPROPS_FOR_CSV) {
      line.append(",");
      line.append(FileFormats.toCsv(sysProps.getProperty(key, "unknown")));
    }
    line.append(",");
    line.append(FileFormats.toCsv(
        log4jVersion,
        propsFromAgent.getProperty("exploited", this.gotLdapConnection ? "vulnerable" : "not vulnerable")));
    print.accept(line.toString());
  }

  public void startServer() throws IOException {
    ServerSocket ss = new ServerSocket();
    ss.bind(null);
    ldapServerPort = ss.getLocalPort();
    Thread t = new Thread(() -> {
      try {
        Socket a = ss.accept();
        gotLdapConnection = true;
        // If we don't close, log4j hangs for a long time!
        a.close();
      } catch (IOException e) {
        //TODO: log?
        e.printStackTrace();
      }
    });
    t.setDaemon(true);
    t.start();
  }

  public void pleaseFinish() {
    pleaseFinish = true;
  }
}

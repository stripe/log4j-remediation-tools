# Confirm vulnerabilities

> Determine with 100% accuracy whether a running JVM is vulnerable

Authoritatively scans all running JVM's for the December 2021 Log4j exploit [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228).
It does this by injecting actual `Logger.error("${jndi:ldap://...})` calls into the running application and checking for
LDAP network requests made by Log4j.

Specifically, this confirms vulnerability to data exfiltration _and_ remote code execution (it does not differentiate between those two).

## Usage

(For now you need to compile using Java 11, but you can run it on any version 8 or 11+.)
```sh
mvn package
```

Java 8:
```sh
java -cp <java-home>/lib/tools.jar:target/is-it-vulnerable-1.0-SNAPSHOT.jar com.stripe.log4j.isitvuln.IsItVuln
```

Java 11:
```sh
java -jar target/is-it-vulnerable-1.0-SNAPSHOT.jar
```

This will attempt to inject code into all JVM's running on the machine, and report status in CSV format.

### Example output

Sample output to `stdout`:

```csv
date,host,tool,version,pid,path,jre,log4j,log4j version,formatMsgNoLookups,ldap trustURLCodebase,rmi trustURLCodebase,cosnaming trustURLCodebase,exploited
2021-12-14T22:58:04.435774Z,st-keithl1,is-it-vuln,1,18742,/Library/Java/JavaVirtualMachines/amazon-corretto-11.jdk/Contents/Home,Amazon.com Inc. - OpenJDK 64-Bit Server VM - 11.0.13,true,false,unknown,unknown,true,none,vulnerable
2021-12-14T22:58:04.435748Z,st-keithl1,is-it-vuln,1,18741,/Library/Java/JavaVirtualMachines/amazon-corretto-11.jdk/Contents/Home,Amazon.com Inc. - OpenJDK 64-Bit Server VM - 11.0.13,true,unknown,unknown,unknown,unknown,none,not vulnerable
```

| date                        | host       | tool       | version | pid   | path                                                                   | jre                                                  | log4j | log4j version | formatMsgNoLookups | ldap trustURLCodebase | rmi trustURLCodebase | cosnaming trustURLCodebase | exploited      |
| --------------------------- | ---------- | ---------- | ------- | ----- | ---------------------------------------------------------------------- | ---------------------------------------------------- | ----- | ------------- | ------------------ | --------------------- | -------------------- | -------------------------- | -------------- |
| 2021-12-14T22:58:04.435774Z | st-keithl1 | is-it-vuln | 1       | 18742 | /Library/Java/JavaVirtualMachines/amazon-corretto-11.jdk/Contents/Home | Amazon.com Inc. - OpenJDK 64-Bit Server VM - 11.0.13 | true  | false         | unknown            | unknown               | true                 | none                       | vulnerable     |
| 2021-12-14T22:58:04.435748Z | st-keithl1 | is-it-vuln | 1       | 18741 | /Library/Java/JavaVirtualMachines/amazon-corretto-11.jdk/Contents/Home | Amazon.com Inc. - OpenJDK 64-Bit Server VM - 11.0.13 | true  | unknown       | unknown            | unknown               | unknown              | none                       | not vulnerable |

The last column is the most important: it is `vulnerable` or `not vulnerable`. If
`vulnerable` this indicates that Log4J did make an HTTP request when logging a `${jndi:...}` string.

It also prints status updates to stderr:

```sh
Will use this jar for agent: /Users/.../target/is-it-vulnerable-1.0-SNAPSHOT.jar
Attempting to attach to to 23378 running org.jetbrains.idea.maven.server.RemoteMavenServer36
Attempting to attach to to 24730 running org.jetbrains.idea.maven.server.RemoteMavenServer36
Attempting to attach to to 36200 running LDAPRefServer
Attempting to attach to to 18741 running org.jetbrains.jps.cmdline.Launcher
Attempting to attach to to 8383 running
Attempting to attach to to 18742 running com.stripe.Repro
Failed to attach to 24730 running org.jetbrains.idea.maven.server.RemoteMavenServer36: com.sun.tools.attach.AgentInitializationException: Agent JAR loaded but agent failed to initialize
Failed to attach to 23378 running org.jetbrains.idea.maven.server.RemoteMavenServer36: com.sun.tools.attach.AgentInitializationException: Agent JAR loaded but agent failed to initialize
Failed to attach to 8383 running : com.sun.tools.attach.AgentInitializationException: Agent JAR loaded but agent failed to initialize
Failed to attach to 36200 running LDAPRefServer: com.sun.tools.attach.AgentInitializationException: Agent JAR loaded but agent failed to initialize
Parsing /var/folders/zd/71fgr5392y79q54tzgc2zn700000gn/T/is-it-vuln501360083800619055/result-18742.csv
unknown,st-keithl1,full,1,18742,/Library/Java/JavaVirtualMachines/amazon-corretto-11.jdk/Contents/Home,Amazon.com Inc. - OpenJDK 64-Bit Server VM - 11.0.13,true,none,false,unknown,unknown,true,none,vulnerable,maybe
Parsing /var/folders/zd/71fgr5392y79q54tzgc2zn700000gn/T/is-it-vuln501360083800619055/result-18741.csv

```

In your running application you should see this output (though if you don't, it doesn't invalidate the CSV printed by the tool itself):

```sh
Attempting to log IsItVuln ExploitAttempt ${jndi:ldap://127.0.0.1:61092/x}
17:39:40.239 [Attach Listener] ERROR com.stripe.log4j.isitvuln.IsItVulnAgent - IsItVuln ExploitAttempt ${jndi:ldap://127.0.0.1:61092/x}
```

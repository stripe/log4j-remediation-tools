# Find vulnerabilities

> Determine heuristically whether a running JVM is vulnerable

## Building

Cross compile for linux with:

```sh
env GOOS=linux GOARCH=amd64 go build -o log4j-finder-amd64-linux *.go
```

## Running

Run with sudo:

```sh
sudo ./log4j-finder-amd64-linux
```

Add verbose for more logging:

```sh
sudo ./log4j-finder-amd64-linux -verbose
```

### Example output

Sample output to `stdout`:

```csv
hostname,tool,tool_sha,pid,java_bin_location,java_version,prop1,prop2,prop3,prop4,using_log4j,oldest_log4j_version,vulnerable,oldest_vulnerable_log4j_version
myhost.stripe.com,lite,5312d3ca2e10757078770b735c83088820627f3cdcb34f3df8d99d16dfe00903,1234,/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java,,,,,,true,2.1,yes,2.1
myhost.stripe.com,lite,5312d3ca2e10757078770b735c83088820627f3cdcb34f3df8d99d16dfe00903,5678,/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java,,,,,,true,2.9.0,yes,2.9.0
myhost.stripe.com,lite,5312d3ca2e10757078770b735c83088820627f3cdcb34f3df8d99d16dfe00903,9999,/usr/lib/jvm/java-11-openjdk-amd64/bin/java,,,,,,true,2.16.0,no,2.16.0
2021/12/14 23:57:18 done
```

| hostname          | tool | tool_sha                                                         | pid  | java_bin_location                              | java_version | prop1 | prop2 | prop3 | prop4 | using_log4j | oldest_log4j_version | vulnerable | oldest_vulnerable_log4j_version |
| ----------------- | ---- | ---------------------------------------------------------------- | ---- | ---------------------------------------------- | ------------ | ----- | ----- | ----- | ----- | ----------- | -------------------- | ---------- | ------------------------------- |
| myhost.stripe.com | lite | 5312d3ca2e10757078770b735c83088820627f3cdcb34f3df8d99d16dfe00903 | 1234 | /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java |              |       |       |       |       | true        | 2.1                  | yes        | 2.1                             |
| myhost.stripe.com | lite | 5312d3ca2e10757078770b735c83088820627f3cdcb34f3df8d99d16dfe00903 | 5678 | /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java |              |       |       |       |       | true        | 2.9.0                | yes        | 2.9.0                           |
| myhost.stripe.com | lite | 5312d3ca2e10757078770b735c83088820627f3cdcb34f3df8d99d16dfe00903 | 9999 | /usr/lib/jvm/java-11-openjdk-amd64/bin/java    |              |       |       |       |       | true        | 2.16.0               | no         | 2.16.0                          |

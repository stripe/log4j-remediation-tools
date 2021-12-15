# `log4j-remediation-tools`

> Tools for finding and reproducing the [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) `log4j2` vulnerability

## Tools

- [`find-vulnerabilities`](./find-vulnerabilities): determine heuristically whether a running JVM is vulnerable
- [`confirm-vulnerabilities`](./confirm-vulnerabilities): determine with 100% accuracy whether a running JVM is vulnerable

## Usage

Both of these tools scan all running JVM processes on a machine, and produce a CSV report about which processes may be / are vulnerable.

Check out the corresponding READMEs for [`find-vulnerabilities/`](./find-vulnerabilities) and [`confirm-vulnerabilities/`](./confirm-vulnerabilities) for usage details.

### Which tool should I use?

Here are a few tradeoffs to help you determine which tool is right for your use case:

`find-vulnerabilities` is low-risk to run, but has the possibility of missing:

- Cases where a system property is not set on the CLI, e.g. at runtime
- Cases where the JVM has closed the file descriptor for the jar
- Non-standard / patched releases of `log4j2`

`confirm-vulnerabilities` uses the JVM Attach API which:

- May not work if an application explicitly disables this API
- May crash the running JVM due to JVM bugs
- May briefly slow down the running JVM while waiting for JVM pause

## License

This project uses the [MIT license](LICENSE.md).

## Code of conduct

This project has adopted the Stripe [Code of conduct](CODE_OF_CONDUCT.md).

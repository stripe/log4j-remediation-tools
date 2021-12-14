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

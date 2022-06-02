# Illumio API Package

[![GoDoc](https://godoc.org/github.com/brian1917/illumioapi?status.svg)](https://godoc.org/github.com/brian1917/illumioapi)

## Description

Go package to interact with the Illumio API.

## Version 2.0 Announcement
Version 2.0 removes redundant code by using the new PCE CRUD methods, standardizes names, and cleans up other tech debt. Renamed or removed methods have been moved to `deprecated.go` to keep backwards compatibility.

## Example Code
All interaction with the PCE are done via methods on the PCE type. For example, the code below prints all hostnames:
```
// Create PCE
pce := illumioapi.PCE{
   FQDN: "bep-lab.poc.segmentationpov.com",
   Port: 443,
   DisableTLSChecking: true}

// Login and ignore error checking for example
pce.Login("brian@email.com", "Password123")

// Get all workloads and ignore error checking for example
wklds, _, _ := pce.GetWklds(nil)

// Iterate through workloads and print hostname
for _, w := range wklds {
    fmt.Println(w.Hostname)
}
```
# Illumio API Package

[![GoDoc](https://godoc.org/github.com/brian1917/illumioapi?status.svg)](https://godoc.org/github.com/brian1917/illumioapi)

## Description

Go package to easily interact with the Illumio API.

## Example Code
Nearly all functions that interact with your PCE are methods on the PCE type. For example, the code below prints all hostnames:
```
// Create PCE
pce := illumioapi.PCE{
   FQDN: "bep-lab.poc.segmentationpov.com",
   Port: 443,
   DisableTLSChecking: true}

// Login and ignore error checking for example
pce.Login("brian@email.com", "Password123")

// Get all workloads and ignore error checking for example
wklds, _, _ := pce.GetAllWorkloads()

// Iterate through workloads and print hostname
for _, w := range wklds {
    fmt.Println(w.Hostname)
}
```

## Tests and Examples ##
The `illumioapi_test` package includes some tests for the package. This can also be referenced for examples on how to use some of the functions. It's not a complete test package.
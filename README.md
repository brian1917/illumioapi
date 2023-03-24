# Illumio API Package

[![GoDoc](https://godoc.org/github.com/brian1917/illumioapi?status.svg)](https://godoc.org/github.com/brian1917/illumioapi)

## Description

Go package to interact with the Illumio API.

## Version 2 Announcement
The new default branch is `v2`. The `v1` branch will be minimally maintained. Version 1 was built as needed and as it evolved there were many things that would have bee done differently from the start. Version 2 looks to address a lot of these. See below for a non-exhaustive list of the major changes:
- Version 2 aims for better consistency for when pointers are used in structs. Pointers are used for custom types, slices, and booleans as well as any integer or string that could need to be cleared in the PCE. For example, an `href` never can be cleared in the PCE so it is a `string`. A `description` could be cleared (e.g., send a `PUT` request to remove a description). In that case it's a `*string` so you can send a blank string with `omitempty` to clear it or a `nil` value to have it omitted.
- Version 2 has some helper functions to deal with all of the pointers in the data structure. `PtrToVal` can be used on any pointer to return its value or blank value if it's `nil`. The goal is to reduce the checking of `nil` before doing a comparison or using a value where appropriate.
- Version 2 does not return slices for getting policy objects. For example `pce.GetWklds` will return just the `API` type and an `err`. The policy objects are populated into the `pce` slices and maps.

## Example Code
All interactions with the PCE are done via methods on the `pce` type. For example, the code below prints all hostnames:
```
// Create PCE
pce := illumioapi.PCE{
   FQDN: "bp-lab.poc.segmentationpov.com",
   Port: 8443,
   DisableTLSChecking: true}

// Login and ignore error checking for example
pce.Login("brian@email.com", "Password123")

// Get all workloads
api, err := pce.GetWklds(nil)
fmt.Println(api.StatusCode)
if err != nil {
    log.Fatal(err)
}

// Iterate through workloads and print hostname
for _, w := range pce.WorkloadsSlice {
    fmt.Println(w.Hostname)
}
```
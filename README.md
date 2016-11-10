# ACME Azure

A powershell script to automate all your Let's Encrypt Certificates usage with Azure WebApps using ACMESharp Module.

## Features

-Creation of Let's Encrypt Certificate

-Completes http01 challenge of an Azure WebApp

-Uploads Let's Encrypt Certificate to Azure WebApp

## Example

ACMEAzure.ps1 -url sample.com -webAppName samplewebapp -domain "sample.com" -aliasCert "certaliasname" -email "sample@outlook.com" -pathToPfx "C:\certlocation" -pfxName "sampleCert"

## Todo

- Add Support for Azure DNS and DNS Challenge Handling

- Add logging

- Handle Certificate Passwords better, possibly a parameter 

## Copyright

Copyright Henry Robalino

Licensed under GPLv3

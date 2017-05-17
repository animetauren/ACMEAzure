# ACME Azure

ACMEAzure.ps1 - An ACMESharp client implementation for Azure WebApps.

Client implementation of the ACMESharp Library that automates and simplifies the tasks of requesting,validating and applying a Let's Encryp Cert to an Azure WebApp. Providing two types of challenge methods DNS and HTTP.

SAN Support is currently in the works, with initial support added.

Renew certificates is currently in the works, with initial support added.

## Features
- Supports http and dns challenge validations.

- Supports http json file verification

- Supports Azure DNS verification

- Supports Vault Profiles either :sys or :user

- Initial Support for SAN validations

- Initiates, requests and completes Let's Encrypt Cert Challenge for Azure WebApp.

- Upload and binds Let's Encrypt SSL Cert on Azure WebApp. 

- Removes expired SSL Certs from Azure WebApp.

- Cleans up the environment when HTTP01 challenge was used.

- Checks to see if LE Auth Certs are installed in Cert Manager.

- Info File created with Information regarding Certificate Request including alias, idenRef and etc.

## Requirements

- [ACMESharp 8.1](https://github.com/ebekker/ACMESharp/)
<<<<<<< HEAD
- [AzureRM] (https://github.com/Azure/azure-powershell) (Tested with latest edition of AzureRM at time of post.)
=======
- [AzureRM](https://github.com/Azure/azure-powershell)
>>>>>>> 2a2cb324c691c0b6f16ff4f2dcdeb42e52cea64e

## Example

```powershell

\ACMEAzure.ps1 -url sample.com -webappname samplewebapp -identifierRef "sampleref1" -aliasCert "samplealiascert" -email sample@outlook.com -ChallengeType "http-01" -pathToPfx "C:\certlocation" -pfxName "sampleCert" -pfxPassword "S3cureP4assw0rd!"
```

## Parameters
```
.PARAMETER url
    Defines the URL of the website for which SSL will be issued to.
    Mandatory parameter
    No default value.
.PARAMETER webAppName
    Defines the name of the Azure WebApp Name that is currently hosting your site.
    Mandatory Parameter
    No default value.
.PARAMETER RGName
    Defines the name of the Resource Group if using ARM
.PARAMETER identifierRef
    A unique idenifier that is referenced in the attempt to create a certificate. This will be submitted with your LE Request. One IdenRef is valid per Cert Request
    Mandatory parameter
.PARAMETER aliasCert
    Defines the alias for the cert that will be used submitted to LE and that will be used by your website.
    Mandatory parameter
    No default value.
.PARAMETER vaultProfile
    Specify a name or vault profile to use, this is helpful for testing, can be either :user or :sys
    No default Value.
.PARAMETER renew
    Bool Param that is required when using the script to renew an existing LE Cert.
    Default set to False.
.PARAMETER SAN
    Bool Param that is required when using the script to get SAN Certificates.
    Default set to False.
.PARAMETER email
    Defines the email used to register the new Let's Encrypt SSL
    Mandatory parameter
    No default Value.
.PARAMETER pathToPfx
    Defines the LE Challenge Type Method to use either http or dns verification.
    Mandatory parameter
    Defaults: http-01 or dns-01
.PARAMETER pathToPfx
    Defines the path location to save the Pfx file to.
    Mandatory parameter
    No default value.
.PARAMETER pfxName
    Defines the name of the pfx cert, if none is set, then Alias Cert + Current Date will be used.
    No default value.
.PARAMETER pfxPassword
    Defines the password of the pfx cert, this value will be converted into a secure string when script is run.
    Mandatory parameter
    No default value.
.PARAMETER subID
    Defines the Azure subscription ID, if none is set, then a menu will be displayed asking to select a sub. 
    No default value.
```

## Todo

- Add logging
- Implement SAN Support Fully
- Implement Cert Renew Fully 

## Copyright

Copyright Henry Robalino

Licensed under GPLv3

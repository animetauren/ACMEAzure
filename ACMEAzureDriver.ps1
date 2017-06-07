<#
.SYNOPSIS
    ACMEAzureDriver.ps1 - An ACMEAzure Deployment Driver Script, automate the deployment of multiple LE Certs on Azure.
.DESCRIPTION
    An ACMEAzure Deployment Script, that consumes a JSON file with the specified configurations and can automate multiple ACMEAzure Deployments to different Websites, using different challenge types, subscriptions and etc.
.PARAMETER JSONPath
    Defines the path location to the JSON file that will be used to launch the deployment.
    Mandatory parameter
    No default value.
.NOTES
    File Name   : ACMEAzureDriver.ps1
    Author      : Henry Robalino - henry.robalino@outlook.com - https://anmtrn.com
    Version     : 1.0 - June 7, 2017
.TODO
    Add Support to bypass multiple checks of initial Azure and ACMESharp when running multiple deployments if the first deployment succeeds. 
    Add 
.EXAMPLE
    PS C:\> .\ACMEAzureDriver.ps1 -JSONPath "C:\temp\lecertfile.json"
#>

param(
        [parameter(Mandatory=$true, HelpMessage='Location to store LE Cert in pfx format. Must be an absolute Path')][ValidateNotNullOrEmpty()]
        [String]$JSONPath
)

#Checks to see if Path for the PFX is valid
if(!([System.IO.Path]::IsPathRooted($JSONPath))){
        Write-Host "The Path you entered is not an absolute path, the JSON File Path must be an absolute path." -ForegroundColor Red
        Write-Host "Exiting..." -ForegroundColor Red
        Exit    
}

$jsonInfoFile = Get-Content -Raw -Path $JSONPath | ConvertFrom-Json 

$deploymentsCount = $jsonInfoFile.Deployments
  
Write-Host "############################################################" -ForegroundColor Green
Write-Host "##############Starting to run Deployments ##################" -ForegroundColor Green
Write-Host "############################################################`n" -ForegroundColor Green

Write-Host "Running Deployments for:`n" $jsonInfoFile.Deployments -ForegroundColor Green

foreach ($deploy in $jsonInfoFile.Deployments){
    
    $deployParamTable = @($jsonInfoFile.$deploy)
    if($deployParamTable.SAN -eq $True){   
        $urlCount = $deployParamTable.URL.Count
        $identRefCount = $deployParamTable.IdentRef.Count
        $webappCount = $deployParamTable.WebApp.Count

        if(($urlCount -ne $identRefCount) -and ($urlCount -ne $webappCount) -and ($identRefCount -ne $webappCount)){
            Write-Host "`nThe number of ULRs, IdentRefs and WebApps do not match. Please fix this and run again. Exiting..." -ForegroundColor Red
            Exit
        }
        else{
            Write-Host "`nInitial Params passed. Continuing...`n" -ForegroundColor Green
            foreach($urlName in $deployParamTable.URL){
                [String]$urlSANString += $urlName
            }
            foreach($identRefName in $deployParamTable.IdentRef){
                [String]$identRefSANString += $identRefName
            }
            foreach($webappName in $deployParamTable.WebApp){
                [String]$webappSANString += $webappName
            }

            try{
            $splatTable = @{"url" = $urlSANString; "webAppName" = $webappSANString; `
            "identifierRef" = $identRefSANString; "aliasCert" = $deployParamTable.AliasCert; `
            "email" = $deployParamTable.Email; "challengeType" = $deployParamTable.ChallengeType; `
            "pathToPfx" = $deployParamTable.PFXPath; "pfxName" = $deployParamTable.PFXName; `
             "SAN" = $True; "pfxPassword" = $deployParamTable.PFXPassword; `
             "subID" = $deployParamTable.AzureSubID}     

            .\ACMEAzure.ps1 @splatTable

             Write-Host "`nFinished Running the deployment for $deploy" -ForegroundColor Red

            }
            catch{
                Write-Host "`nThere was an error running the ACMEAzureDriver. Exiting...`n" -ForegroundColor Red
                $_
                Exit
            }
        }
    }
    else{
        
        try{
        $splatTable = @{"url" = $deployParamTable.URL; "webAppName" = $deployParamTable.WebApp; `
        "identifierRef" = $deployParamTable.IdentRef; "aliasCert" = $deployParamTable.AliasCert; `
        "email" = $deployParamTable.Email; "challengeType" = $deployParamTable.ChallengeType; `
        "pathToPfx" = $deployParamTable.PFXPath; "pfxName" = $deployParamTable.PFXName; ` 
        "pfxPassword" = $deployParamTable.PFXPassword; "subID" = $deployParamTable.AzureSubID}
        
        .\ACMEAzure.ps1 @splatTable

        Write-Host "`nFinished Running the deployment for $deploy" -ForegroundColor Red
        
        }
        catch{
            Write-Host "`nThere was an error running the ACMEAzureDriver. Exiting...`n" -ForegroundColor Red
            $_
            Exit
        }
    }
}
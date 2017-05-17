<#
.SYNOPSIS
    ACMEAzure.ps1 - An ACMESharp client implementation for Azure WebApps.
.DESCRIPTION
    Client implementation of the ACMESharp Library that automates and simplifies the tasks of requesting,validating and applying a Let's Encryp Cert to an Azure WebApp. Providing two types of challenge methods DNS and HTTP.
.Credits
    ACMESharp - https://github.com/ebekker/ACMESharp
    Kudu - https://github.com/projectkudu/kudu 
    Let's Encrypt - https://letsencrypt.org/
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
.NOTES
    File Name   : ACMEAzure.ps1
    Author      : Henry Robalino - henry.robalino@outlook.com - https://anmtrn.com
    Version     : 1.6 - May 17, 2017
.TODO
    Add option to renew certs already validated.
    Clean up certs on Azure WebApp
    Add more examples one for renew, one for san, one for renew with san.
.EXAMPLE
    PS C:\> .\ACMEAzure.ps1 -url sample.com -webappname samplewebapp -identifierRef "sampleref1" -aliasCert "samplealiascert" -email sample@outlook.com -ChallengeType "http-01" -pathToPfx "C:\certlocation" -pfxName "sampleCert" -pfxPassword "S3cureP4assw0rd!"
#>

param(
		[parameter(Mandatory=$true, HelpMessage='The url of your website.')][ValidateNotNullOrEmpty()]
        [String]$url,
		[parameter(Mandatory=$true, HelpMessage='The name of the WebApp where the website resides in.')][ValidateNotNullOrEmpty()]
        [String]$webAppName,
		[parameter(Mandatory=$true, HelpMessage='A unique idenifier that is referenced in the attempt to create a certificate.')][ValidateNotNullOrEmpty()]
        [String]$identifierRef,
        [parameter(Mandatory=$true, HelpMessage='The Alias of the Cert being created for this website.')][ValidateNotNullOrEmpty()]
        [String]$aliasCert,
        [parameter(Mandatory=$true, ParameterSetName="new", HelpMessage='Email Address associated with this Certificate.')][ValidateScript({
            If ($_ -match '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$') {
                $True
            }
            else {
                Throw "$_ is not a valid email, please use a valid email and try again."
            }
        })][string]$email,
        [parameter(Mandatory=$false, HelpMessage='Vault Profile Name, you use :user for Staging Testing and :sys for live testing.')][ValidateSet(":user", ":sys")]
        [String]$vaultProfile = ":sys",
        [parameter(Mandatory=$false, ParameterSetName="renew", HelpMessage='Renew flag, only set to true to renew an expiring certificate.')][ValidateNotNullOrEmpty()]
        [bool]$renew = $false,
        [parameter(Mandatory=$false, HelpMessage='SAN Flag, allows for multiple domain name registration.')][ValidateNotNullOrEmpty()]
        [bool]$SAN = $false,
        [parameter(Mandatory=$true, ParameterSetName="new", HelpMessage='Which ACME challenge method to use, "http-01" or "dns-01"')][ValidateSet("http-01", "dns-01")]
        [string]$challengeType,
        [parameter(Mandatory=$true, HelpMessage='Location to store LE Cert in pfx format. Must be an absolute Path')][ValidateNotNullOrEmpty()]
        [String]$pathToPfx,
        [parameter(Mandatory=$false, HelpMessage='If none chosen then it will be following: aliascert_mmddyy')][ValidateNotNullOrEmpty()]
        [String]$pfxName,
        [parameter(Mandatory=$true, HelpMessage='The Password for the PFX file. Please make it a complex password!')][ValidateNotNullOrEmpty()]
        [String]$pfxPassword,
        [parameter(Mandatory=$false, HelpMessage='Azure Sub ID where the WebApp lives.')][ValidateNotNullOrEmpty()]
        [String]$subID = $null,
        [parameter(Mandatory=$false, ParameterSetName="new", HelpMessage='Only needed if selecting "dns-01" as Challenge Type')][ValidateNotNullOrEmpty()]
        [String]$dnsZone

)

############################################################
# Param Checks
############################################################

function Check-SANParams($urlSAN,$webAppNameSAN, $identifierRefSAN){

    $urlSANArr = $urlSAN.Split(",")
    $webAppNameSANArr = $webAppNameSAN.Split(",")
    $identifierRefSANArr = $identifierRefSAN.Split(",")

    if(($urlSANArr.count -ne $webAppNameSANArr.count) -or ($urlSANArr.count -ne $identifierRefSANArr.count)){
        Write-Host "Number of urls, webapp names and Identifier Refs do not match! They need to match, please try agian. Exiting..." -ForegroundColor Red
        Exit
    }

    $urlBaseSuffixTLD = $urlSANArr[0].split(".")[-1]
    $urlBaseSuffixName = $urlSANArr[0].split(".")[-2]

    $i = 0
    foreach($urlSANItem in $urlSANArr){
        $urlSANItemTLD = $urlSANItem.split(",")[-1]         
        $urlSANItemName = $urlSANItem.split(",")[-2]
        
        if(($urlSANItemTLD -ne $urlSANItemTLD) -or ($urlSANItemName -ne $urlBaseSuffixName)){
            Write-Host "`nThe URLs for SAN do not match, at either a TLD or Domain Name Level. Please Fix." -ForegroundColor Yellow    
            Write-Host "The URLs should match the following:" -ForegroundColor Yellow
            Write-Host "TLD: $urlBaseSuffixTLD and Domain Name: $urlBaseSuffixName" -ForegroundColor Yellow
            Write-Host "Exiting now..." -ForegroundColor Red
            Exit
        }
        else{
            Write-Host "Checking the site: $urlSANItem and the WebApp:" $webAppNameSANArr[$i]
            $checkParamRGName,$checkParamWebAppObj = Check-AzureParams $urlSANItem $webAppNameSANArr[$i] 
            $RGNameArr += ,$checkParamRGName
            $WebAppObjArr += ,$checkParamWebAppObj
            Write-Host "Finished checking the site: $urlSANItem and the WebApp:" $webAppNameSANArr[$i]
            $i++
        }
    }#Closes Foreach

    $urlSANArr
    $webAppNameSANArr
    $identifierRefSANArr
    $RGNameArr
    $WebAppObjArr        
}

function Check-ACMEParams{
    
    Write-Host "Checking ACME Params: IdentifierRef, aliasCert and SAN Flags"
    if($identifierRef[0] -match '[0-9]'){
        Write-Host "Your AliasCert seems to start with a number, it cannot start with a number. Exiting..." -ForegroundColor Red
        Exit
    }
    try{
        if((Get-ACMEIdentifier | Where-Object {$_.alias -eq "$identifierRef"}) -and (!$renew)){
            Write-Output "There is an Identifier Reference with same name in the Vault Already and cannot be used again. Exiting..."
            Exit
        }
        elseif((Get-ACMEIdentifier | Where-Object {$_.alias -ne "$identifierRef"}) -and ($renew)){
            Write-Ouput "The Identified Reference Name specified to be used for the renewal process is not located in the vault."
            Write-Output "The Identified Reference Name must be the same name specified when the first LE Cert was created for $url"
            Write-Output "================ Current Alias' listed in the Vault ================"
            (Get-ACMEIdentifier).Alias
        }
    }
    catch{
        Write-Verbose "There are no Identifiers in the vault. The error caught can safely be ignored."
    }
    Write-Verbose "Finished Checking IdentifierRef. Next checking AliasCert."
    try{
        if((Get-ACMECertificate | Where-Object {$_.Alias -eq $aliasCert})){
            Write-Host "$aliasCert was already used once as an Alias Cert and cannot be used again. Exiting..." -ForegroundColor Red
            Exit
        }
    }
    catch{
        Write-Verbose "There are no Alias Certs in the vault. The error caught can be safely ignored."
    }
    Write-Host "Finished Checking Alias Cert. ACMEParams are fine, continuing with script."
}

############################################################
# ACMEAzure Initial Checks
############################################################

function Check-AzureParams($url, $webAppName){
    
    Write-Output "Checking Azure Parameters..." 
    $status = (Invoke-WebRequest $url -MaximumRedirection 0 -ErrorAction SilentlyContinue)
    if($status.StatusCode -eq "301"){
        Write-Verbose "Checking if Redirection is being set to https of same url."
        if($status.Links.href -notmatch "https://" -or $status.Links.href -notmatch $url){
            Write-Verbose "Redirection is not being set to https of same url. Cannot Validate URL. Exiting."    
            Exit
        }
        else{
            Write-Verbose "URL Redirection is valid, continuing."
        }               
    }
    elseif($status.StatusCode -ne "200"){
        Write-Verbose "URL is not valid, Please try again.Exiting..."
        Exit
    }
    else{
        Write-Verbose "URL is valid, continuing."
    }

    $websiteObj = Get-AzureRmWebApp -Name $webAppName
    $RGName = $websiteObj.ResourceGroup
    $websiteResourceObj = (Get-AzureRmResource -ResourceType Microsoft.Web/sites -ResourceName "$webAppName" -ResourceGroupName $RGName)
    $skuWebApp = $websiteResourceObj.Properties.Sku
    if(!$websiteObj){
        Write-Verbose "WebApp $webAppName does not exist. Exiting"
        Exit
    }
    elseif($websiteObj.State -ne "Running"){
        Write-Verbose "The WebApp is currently stopped, please fix and make sure WebApp state is running. Exiting..."
        Exit
    }
    elseif(($challengeType -eq "http-01") -and ($websiteObj.ScmSiteAlsoStopped)){
        Write-Verbose "SCM Site for the webApp: $webAppName is in the stop state, please fix before re-running. Exiting..."    
        Exit
    }
    elseif(($websiteObj.HostNames[0] -ne $url) -and ($websiteObj.HostNames[1] -ne $url)){
        Write-Verbose "This Url does not belong to this WebApp. Exiting"
        Exit
    }
    elseif(($skuWebApp -ne "Basic") -and ($skuWebApp -ne "Standard")){
        Write-Verbose "The WebApp: $webAppName does not have the right sku, it needs to be either basic or standard. Please upgrade plan and retry. Exiting..."
        Exit
    }
    else{
        $RGName = $websiteObj.ResourceGroup
        Write-Verbose "WebApp Name is Valid, meets the requirements. Grabbed Resource Group Name."
    }

    Write-Output "Finished checking Azure Parameters, continuing..."
    
    $RGName
    $websiteObj    
}

function Show-Menu{

     #cls
     Write-Output "================ Select Azure Subscription ================"
     try{
         $allSub = (Get-AzureRmSubscription)
     }
     catch{
        Write-Output "Login into your Azure Subscription"
        Login-AzureRmAccount
        $allSub = Get-AzureRmSubscription
     }
    
    $inputOk = $false
    $i = 0
    Foreach($sub in $allSub){
        $subName = @(,$sub.SubscriptionName)
        $subsID += @(,$sub.SubscriptionId)
        Write-Output "$($i): Press '$i' to select this Subscription: $subName"
        $i++
    }
    Write-Output "Q: Press 'Q' to quit.`n"
    do{
        try{
            $subSelectedEntry = Read-Host
            if($subSelectedEntry -eq "q"){
                Write-Output "Exiting Azure Subscription Login Attempt"
                $inputOk = $true   
                Exit
            }
            [int]$subSelectedEntry = [convert]::ToInt32($subSelectedEntry, 10)
            if($subSelectedEntry -lt $allSub.Count){
                Write-Output "`nAzure Subscription Selected:"
                Select-AzureRmSubscription -SubscriptionId $subsID[$subSelectedEntry]
                $inputOk = $true
            }
            else{
                Write-Output 'Your input was not valid, it can either be a "Q" or a number listed above.'
            }       
        }
        catch{
            Write-Output "Try Input Again, it has to be a number and one of the specified above."
        }
    }
    until($inputOk)

    $i = $null        
}

############################################################
# Check ACMESharp & AzureRM Module are installed.
############################################################

function Check-IntLECerts{

    $intermediatecerts = Get-Childitem 'cert:\CurrentUser\CA' -Recurse | Where {$_.Subject -like "CN=Let's Encrypt Authority X3*"}
    if(!$intermediatecerts){
        Write-Host "Let's Encrypt Intermediate Certificates are missing from your CertMgr." -ForegroundColor Red
        Write-Host "These Intermediate Certs are necessary, for ACMEAzure to run." -ForegroundColor Red
        Write-Host "You can find these certs here: https://letsencrypt.org/certificates/" -ForegroundColor Green
        Write-Host "Import the intermediate certs into the Intermediate Certificate Authorities\Certificate Folder in CertMgr.msc" -ForegroundColor Green
        Write-Host "Then run this script again. Exiting..."
        Exit
    }
}

function Check-Modules{

    Write-Host "Checking if ACMESharp Module is installed..."
    if(Get-Module -ListAvailable -Name ACMESharp) {
        Import-Module -Name ACMESharp
        Write-Host "Module exists continuing...`n"
    }
    else{
        Write-Host "Module does not exist...installing Module"
        Install-Module -Name ACMESharp
        . $profile
        Import-Module -Name ACMESharp
        Write-Host "ACMESharp Module has been installed!`n"
    }

    Write-Host "Checking if AzureRM Module is installed..."
    if((Get-Module -ListAvailable -Name AzureRM.*)) {
        Write-Host "Module exists continuing...`n"
    }
    else{
        Write-Host "Module does not exist...installing Module"
        Install-Module -Name AzureRM
        . $profile
        Import-Module -Name AzureRM
        Write-Host "AzureRM Module has been installed!`n"
    }
}

function Get-PassfromSecureString($pfxPassString){

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pfxPassString)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    $PlainPassword
}

############################################################
# http-01 Challenge
############################################################

function Initialize-KuduAPI($RGName,$websiteObj ){

    Write-Host "Initializing Kudu API"

    $creds = Invoke-AzureRmResourceAction -ResourceGroupName $RGName -ResourceType Microsoft.Web/sites/config -ResourceName $webAppName/publishingcredentials -Action list -ApiVersion 2015-08-01 -Force

    $username = $creds.Properties.PublishingUserName
    $password = $creds.Properties.PublishingPassword
    $script:base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))
    $script:userAgent = "powershell/1.0"
    $apiBaseUrl = "https://$($websiteObj.SiteName).scm.azurewebsites.net/api"
    Write-Host "Finished Initializing Kudu API"

}

function Check-WebConfig ($apiVFSBaseUrl){

    Write-Verbose "Checking if WebConfig File exists..."
    try{
        $checkWebConfigFile = (Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -UserAgent $script:userAgent -Method GET) | where {$_.name -eq "Web.config"}
    }
    catch{
        Write-Host "There seems to have been an error sending the REST request. Please see error below. Exiting..." -ForegroundColor Red
        $_
        Exit
    }
    #Checking if Web.config file exists and  if it is not empty, if so download it, save the original file to a temp location. Then we can modify the Web.config file to upload, while not messing up original Web.config File.
    if($checkWebConfigFile -and ($checkWebConfigFile.size -gt 0)){
        
        Write-Verbose "Web.config File located inside the WebApp Directory."
        try{
            $WebConfigFile = [xml](Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method GET)
        }
        catch{
            Write-Host "There was an error grabbing your Web.config file, please see error below.Exiting..." -ForegroundColor Red
            $_
            Exit
        }
        if(!(Test-Path "$Env:Temp\OriginalWebConfig-$date")){
            mkdir -Path "$Env:Temp\OriginalWebConfig-$date"
        }

        $WebConfigFile.save("$Env:Temp\OriginalWebConfig-$date\Web.config") 
        Write-Verbose "Finished saving original Web.config file, this config will be restored once process finishes."
        }
    #No WebConfig File exists or it is empty, a new one needs to be created with minimal configs needed for LE Challenge
    else{
        Write-Verbose "No Web.config File was located inside your wwwroot directory, or if there was it was an empty file."
        Write-Verbose "Creating Web.config File inside your wwwroot directory this will just allow hosting of json files without extension."
        Write-Verbose "This is necessary to complete the manual http-1 challenge."
        Write-Verbose "This will not modify or add any other access rules to your wwwroot web.config file."
        Write-Verbose "This config file will be removed once the script finishes running successfully."

$WebConfigValue = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <staticContent>
        <remove fileExtension=".json" />
        <mimeMap fileExtension=".json" mimeType="application/json" />
        <remove fileExtension="." />
        <mimeMap fileExtension="." mimeType="text/json" />
    </staticContent>
  </system.webServer>
</configuration>
'@ 

        $WebConfigValue | Out-File "$Env:Temp\Web.config" -Force

        $WebConfigFile = Get-Item -Path "$Env:Temp\Web.config"

        Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method PUT -InFile $WebConfigFile
        Write-Verbose "Web.config file created and uploaded successfuly."
    }

    Write-Verbose "Checking if web.config has static content, if not append that to web.config file"
    if(!$WebConfigFile.configuration.'system.webServer'.staticContent){
        Write-Verbose "Web.config file did not have StaticContent configured, modifying now..."
        
        #Editing the XML File 
        $xmlWC = [xml](Get-Content $WebConfigFile)
        [IO.File]::WriteAllLines($WebConfigFile, $xmlWC)

        #Creates the System.webserver node
        $xmlEltWS = $xmlWC.CreateElement("system.webServer")

        #Creation of the staticContent node
        $xmlSubEltWSSC = $xmlWC.CreateElement("staticContent")

        #region creation of the first remove node
        $xmlSubEltWSSCR = $xmlWC.CreateElement("remove")
        $xmlAttR = $xmlWC.CreateAttribute("fileExtension")
        $xmlAttR.Value = ".json"
        $xmlSubEltWSSCR.Attributes.Append($xmlAttR)
        $xmlSubEltWSSC.AppendChild($xmlSubEltWSSCR)
        #endregion closes remove sub

        #region creation of the first mimeMap Node
        $xmlSubEltWSSCM = $xmlWC.CreateElement("mimeMap")
        $xmlAttR = $xmlWC.CreateAttribute("fileExtension")
        $xmlAttR.Value = ".json"
        $xmlSubEltWSSCM.Attributes.Append($xmlAttR)
        $xmlAttR = $xmlWC.CreateAttribute("mimeType")
        $xmlAttR.Value = "application/json"
        $xmlSubEltWSSCM.Attributes.Append($xmlAttR)
        $xmlSubEltWSSC.AppendChild($xmlSubEltWSSCM)
        #endregion closes the first mimeMap Node

        #region creation of a second remove sub element
        $xmlSubEltWSSCR = $xmlWC.CreateElement("remove")
        $xmlAttR = $xmlWC.CreateAttribute("fileExtension")
        $xmlAttR.Value = "."
        $xmlSubEltWSSCR.Attributes.Append($xmlAttR)
        $xmlSubEltWSSC.AppendChild($xmlSubEltWSSCR)
        #endregion closes second remove sub element

        #region Creation of a second mimeMap sub element
        $xmlSubEltWSSCM = $xmlWC.CreateElement("mimeMap")
        $xmlAttR = $xmlWC.CreateAttribute("fileExtension")
        $xmlAttR.Value = "."
        $xmlSubEltWSSCM.Attributes.Append($xmlAttR)
        $xmlAttR = $xmlWC.CreateAttribute("mimeType")
        $xmlAttR.Value = "text/json"
        $xmlSubEltWSSCM.Attributes.Append($xmlAttR)
        $xmlSubEltWSSC.AppendChild($xmlSubEltWSSCM)
        #endregion closes second mimeMap Sub Element

        #closes the staticContent Node
        $xmlEltWS.AppendChild($xmlSubEltWSSC)
                
        # closes the system.webserver node to the document
        $xmlWC.LastChild.AppendChild($xmlEltWS);

        #Saves the XML File
        $xmlWC.Save("$Env:Temp\Web.config")
        
        $WebConfigFile = Get-Item -Path "$Env:Temp\Web.config"
         
        Write-Verbose "Finished Modifying Web.config File, time to upload file..."

        try{
            Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method PUT -InFile $WebConfigFile 
        }
        catch{
            Write-Host "There was an error uploading the challenge file to your website root folder, see error below. Exiting..." -ForegroundColor Red
            $_
            Exit
        }
        Write-Host "Finished adding Web.config file..." -ForegroundColor Green
    }

    $checkWebConfigFile
}

function Check-SCMDirStructure{

    Write-Verbose "Checking the SCM Directory..."
    
    $wellknown = Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method GET | Where-Object {$_.name -eq ".well-known"} -ErrorAction Stop

    #Checking if .well-known dir exists

    if($wellknown){
        $acmeChallenge = Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/.well-known/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method GET | Where-Object {$_.name -eq "acme-challenge"} -ErrorAction SilentlyContinue
        if($acmeChallenge){
            ####CHECK how this works with mulitple files inside the dir
            $acmeChallengeName = (Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method GET).name
            Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/$acmeChallengeName" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method DELETE
        }
        else{
            Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method PUT        
        }
    }
    else{
        Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method PUT
    }
    Write-Verbose "Finished checking SCM Directory and configuiring the file paths."
}

function Add-Http01ChallengeToSite($compACMEChall, $url){

    Write-Host "Creating Challenge File to Upload..." -ForegroundColor Green

    $acmeChallengeJSONFileValue = $compACMEChall.Challenges.challenge.FileContent

    $acmejsonFile = $acmeChallengeJSONFileValue.split(".")[0]

    New-Item -Path "$Env:Temp" -Name $acmejsonFile -Value $acmeChallengeJSONFileValue -Force | Out-Null
    $acmeChallengeFile = (Get-ChildItem -Path "$Env:Temp\$acmejsonFile")

    Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/$acmejsonFile" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method PUT -InFile $acmeChallengeFile 
    
    Write-Host "Finished creating and uploading challenge file to your site.`n" -ForegroundColor Green

    $challengeSite = "$url/.well-known/acme-challenge/$acmejsonFile"

    $challengeSite
}

function Check-ChallengeFile($challUrl){  
    $challUrlResponse = Invoke-WebRequest $challUrl[1].ToString() -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if($challUrlResponse.Content -eq "The page cannot be displayed because an internal server error has occurred."){
        Write-Host "It seems like WebApp is not up, or specific directory of the website is not accessible." -ForegroundColor Red
        Write-Host "This needs to be fixed before the script can be run successfuly, please check the health of your WebApp or the Web.cofig file..." -ForegroundColor Red
        Write-Host "Exiting..." -ForegroundColor Red
        Exit
    }
}

function Clean-Http01ChallengeToSite($checkWebConfigFile){

    Write-Host "Cleaning up HTTP01 Challegenge Files from WebApp"
    if($checkWebConfigFile){
         Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method DELETE
         $originalWebConfigFile = (Get-ChildItem -Path "$Env:Temp\OriginalWebConfig-$date\Web.config")
         Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method PUT -InFile $originalWebConfigFile
    }
    else{
         Invoke-RestMethod -Uri "$script:apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method DELETE  
    }
    try{
        $lOfVFS = ($script:apiVFSBaseUrl.Length-3)
        $apiVFSBaseURLCMD = $script:apiVFSBaseUrl.substring(0,$lOfVFS) + "command"
        $jsonCMD = @{dir="site\wwwroot";command="rm -r .well-known"} | ConvertTo-Json
        Invoke-RestMethod -Uri $apiVFSBaseURLCMD -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -ContentType application/json -Method POST -Body $jsonCMD
    }
    catch{
        $_
    }
    Write-Host "Finished Cleaning up HTTP01 Challenge Files"
}

############################################################
# dns-01 Challenge
############################################################

function Add-Dns01ChallengeToSite ($compACMEChall){
    
    Write-Host "Checking to see if DNS Zone exists for this WebApp and URL..."
    $dnsZoneCheck = Get-AzureRmDnsZone | Where-Object {$_.Name -eq $dnsZone}
    if(!$dnsZoneCheck){
        Write-Verbose "There are no Azure DNS Records that match Zone: $dnsZone."
        Write-Verbose "Please confirm name and try again. Exiting..."
        Exit
    }
    else{
        $dnsZoneRGName = $dnsZoneCheck.ResourceGroupName 
    }
    Write-Verbose "DNS Zone Record does exist for this WebApp. Continuing..."
    Write-Verbose "Creating DNS TXT Record..."
    
    #Azure DNS does not want full fqdn
    $dnsRRInfo = ($compACMEChall.Challenges | Where-Object {$_.Type -eq "dns-01"}).Challenge
    $dnsRRName = $dnsRRInfo.RecordName.split(".")[0] #Azure DNS does not want full fqdn
    $dnsRRValue = $dnsRRInfo.RecordValue

    $Record = New-AzureRmDnsRecordConfig -Value $dnsRRValue
    $RecordSet = New-AzureRmDnsRecordSet -Name $dnsRRName -RecordType TXT -ResourceGroupName $dnsZoneRGName -TTL 3600 -ZoneName $dnsZone -DnsRecords $Record

    Write-Host "Finished creating TXT Record Set on Azure DNS for $url"
    
    $dnsRRName
    $dnsZoneRGName
}

function Clean-Dns01ChallengeOnSite($dnsRRName, $dnsZoneRGName){

    Remove-AzureRmDnsRecordSet -Name $dnsRRName -RecordType TXT -ZoneName $dnsZone -ResourceGroupName $dnsZoneRGName [-Force]

}

############################################################
# Gettig LE Cert, Uploading Azure WebApp and Checking Cert
############################################################

function Check-CertToSite($RGName) {

    Write-Host "Checking if SSL Binding was succesful..."
    $certChecked = Get-AzureRmWebAppSSLBinding -ResourceGroupName $RGName -WebAppName $webAppName
    $sslCount = 0
    ###Check logic for while loop thoroughly
    while(!$certChecked -and ($sslCount -ne 4)){
        Write-Verbose "SSL Binding was not succesful, let's try checking a few more times..."
        sleep -Seconds 2
        $sslCount++
        $certChecked = Get-AzureRmWebAppSSLBinding -ResourceGroupName $RGName -WebAppName $webAppName
    }

    if($certChecked){
        Write-Host "All Finished! $url has been updated with the new cert!!!" -ForegroundColor Green   
    }
    else{
        Write-Host "********* Woops! There was an error and your website was not updated with a new Cert, please try again!*********" -ForegroundColor Red
        Write-Host "The reccommendation is to either manually upload the cert to the WebApp or running it via PowerShell." -ForegroundColor Red
        Write-Host "Do not run this script again to just add your cert to the WebApp, this will only create another cert for you." -ForegroundColor Red
    }
}

function Clean-WebAppCertPool($RGName, $webAppName, $url){

    Write-Host "Starting the cleaning process..."
    $certPool = Get-AzureRmWebAppCertificate -ResourceGroupName $RGName
    $currDate = Get-Date
    foreach($cert in $certPool){
        if(($cert.ExpirationDate -lt $currDate) -and ($cert.SubjectName -eq $url)){
            Write-Verbose "Removing the Certificate for URL $url with Thumbprint $($cert.Thumbprint)"
            try{
                Remove-AzureRmWebAppSSLBinding -ResourceGroupName $RGName -WebAppName $webAppName -Name $cert.SubjectName -Force
                Write-Verbose "Finished Removing the Certificate for URL $url with Thumbprint $($cert.Thumbprint)"
            }
            catch{
                Write-Host "There was an error removing the binding or deleting the certificate. Please check Permissions. Exiting." -ForegroundColor Red
                Write-Output $_
                Exit
            }
        } 
    }

    Write-Host "Finished cleaning out old expired certs!" -ForegroundColor Green
}

function Renew-ACMECert($RGName){
    
    Write-Host "Starting to Renew ACME Certs"
    $checkSSLWebApp = Get-AzureRmWebAppSSLBinding -ResourceGroupName $RGName -WebAppName $webAppName -ErrorAction SilentlyContinue
    while($checkSSLWebApp){
        Write-Verbose "Removing expired cert to make room for new renewed cert..."
        Remove-AzureRmWebAppSSLBinding -ResourceGroupName $RGName -WebAppName $webAppName -Name $url
        sleep -Seconds 3
        $checkSSLWebApp = Get-AzureRmWebAppSSLBinding -ResourceGroupName $RGName -WebAppName $webAppName -ErrorAction SilentlyContinue
        Write-Verbose "Checking WebApp $webAppName to make sure expired certs are no longer binded..."
    }
    Write-Host "$webAppName is clean from expired SSL certs. We can now update the WebApp with fresh certs..." -ForegroundColor Green

}

############################################################
# LE Cert Info File
############################################################

function Create-LECertInfo{
    param(
    $pathToPfx,
    $url,
    $identifierRef, 
    $date, 
    $aliasCert,
    $challengeType,
    $webAppName,
    $subID,
    $pfxName,
    $SAN
    )    

    Write-Verbose "Outputting Information to Text File Regarding Current LE Cert Generation..."
    Write-Verbose "Saving to $pathToPfx"
    $infoPath = $url + "_" + ($date) + ".txt"
    Out-File -FilePath $pathToPfx\$infoPath
    $date = Get-Date -Format MM/dd/yyyy
    $user = (Get-AzureRmContext).Account.Id     
    $info = `
"AliasCert:$aliasCert
IdentRef:$identifierRef
URL:$url
ChallengeType:$challengeType
SAN:$SAN
WebApp Name:$webAppName
Azure SubscriptID:$subID
Name of PFX Cert:$pfxName
User:$user
Date:$date"

    Add-Content -LiteralPath $pathToPfx\$infoPath -Value $info
    Write-Host "The Location of the InfoFile is: $pathToPfx\$infoPath"

}

############################################################
# ACME Functions
############################################################

function Check-ACMEIdentifierStatus($identifierRef){

    Write-Host "Updating the ACMEIdentifier and checking to see if challenge has worked..."
    if($challengeType -eq "http-01"){
        $idenCount = 0
        do{
            $identRefStatus = ((Update-ACMEIdentifier $identifierRef -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).Status
            sleep -Seconds 5
            $idenCount++
            $identRefStatus = ((Update-ACMEIdentifier $identifierRef -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).Status
            if($identRefStatus -eq "invalid"){
                Write-Host "HTTP-01 Challenge Verification has failed for the following Identifier Reference $identifierRef" -ForegroundColor Red
                Exit
            }
        }until($identRefStatus -eq "valid" -or $idenCount -gt 12)
    }
    else{
        $identRefStatus = ((Update-ACMEIdentifier $identifierRef -ChallengeType dns-01).Challenges | Where-Object {$_.Type -eq "dns-01"}).Status
        do{
            $identRefStatus = ((Update-ACMEIdentifier $identifierRef -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).Status
            sleep -Seconds 5
            $idenCount++
            $identRefStatus = ((Update-ACMEIdentifier $identifierRef -ChallengeType dns-01).Challenges | Where-Object {$_.Type -eq "dns-01"}).Status
            if($identRefStatus -eq "invalid"){
                Write-Host "DNS-01 Challenge Verification has failed for the following Identifier Reference $identifierRef" -ForegroundColor Red
                Exit
            }
        }until($identRefStatus -eq "valid" -or $idenCount -gt 12)
    }
    Write-Host "Finished Updating the ACMEIdentifier..."
}

############################################################
# ACMEAzure Core
############################################################

function Start-ACMESharp{

    param(
    [string]$url, 
    [string]$webAppName, 
    [string]$RGName, 
    [System.Object]$websiteObj, 
    [string]$dnsZone, 
    [string]$aliasCert, 
    [string]$identifierRef, 
    [bool]$renew, 
    [string]$email, 
    [string]$challengeType,
    [string]$date, 
    [string]$index
    )

if(!$renew){

    if($index -eq 0){
        Write-Verbose "Index is set to 0, meaning that we need to do our ACME Registration, this will only happen this one time."
        New-ACMERegistration -Contacts mailto:$email -AcceptTos
        Write-Verbose "ACME Registration is completed..."
    }
    Write-Verbose "Setting up ACME Identifier for: $url"
    New-ACMEIdentifier -Dns $url -Alias $identifierRef

    if($challengeType -eq "http-01"){
        
        Initialize-KuduAPI $RGName $websiteObj

        $compACMEChall = Complete-ACMEChallenge $identifierRef -ChallengeType http-01 -Handler manual

        #VFS URL API
        $script:apiVFSBaseUrl = "https://$($websiteObj.SiteName).scm.azurewebsites.net/api/vfs"

        #Checks WebConfig to make sure json files can be added so challenge can succeed, returns the Web.Config File
        $WebConfigFile = Check-WebConfig $script:apiVFSBaseUrl

        #Checks the SCM Directory making sure that the right folders exist, if not create them.
        Check-SCMDirStructure

        #Adds the challenge json to the right dir in the Azure site. 
        $challengeReturn = Add-Http01ChallengeToSite $compACMEChall $url

        #Checks that Challenge is accessible.
        Check-ChallengeFile $challengeReturn

        #Submit the challenge to LE Server
        try{
            Submit-ACMEChallenge -IdentifierRef $identifierRef -ChallengeType http-01
        }
        catch{
            if($_ -like "Error creating new cert :: too many certificates already issued for exact set of domains*"){
                Write-Host "There are too many Certificates issued for $url already." -ForegroundColor Red
            }
            else{
                Write-Host "Something went wrong submitting the ACME Challenge, please see the error below. Exiting..." -ForegroundColor Red
                $_
            }
            Exit
        }
        Check-ACMEIdentifierStatus $identifierRef
    
    }
    else{

        $compACMEChall = Complete-ACMEChallenge $identifierRef -ChallengeType dns-01 -Handler manual
    
        #Adds the challenge json to the right dir in the Azure site. 
        $dnsRRName, $dnsZoneRGName = Add-Dns01ChallengeToSite $compACMEChall

        #Submit the challenge to LE Server
        try{
            Submit-ACMEChallenge $identifierRef -ChallengeType dns-01
        }
        catch{
            if($_ -like "Error creating new cert :: too many certificates already issued for exact set of domains*"){
                Write-Host "There are too many Certificates issued for $url already." -ForegroundColor Red
            }
            else{
                Write-Host "Something went wrong submitting the ACME Challenge, please see the error below. Exiting..." -ForegroundColor Red
                $_
            }
            Exit
        }
        Check-ACMEIdentifierStatus $identifierRef

        return $dnsRRName, $dnsZoneRGName
    }     

}

if($renew){
    Renew-ACMECert $RGName
}

}

function Run-CertGeneration{

    param(
    [string]$identifierRefArr, 
    [string]$aliasCert, 
    [string]$pfxName, 
    [string]$pathToPfx,
    [System.Security.SecureString]$pfxpassSecure,  
    [bool]$SAN
    )

    if($SAN){
        Write-Host "Generating New ACME Cert for the renew request..."
        $idenRefEndRange = $identifierRefArr.count-1
        $identifierRef = $identifierRefArr[0]
        $identifierRefsAlt = $identifierRefArr[1..$idenRefEndRange]
        New-ACMECertificate $identifierRef -Generate -AlternativeIdentifierRefs $identifierRefsAlt -Alias $aliasCert
        Write-Host "Finished Generating New ACME Cert for the renew request..."        
    }
    else{
        Write-Verbose "Generating New ACME Cert for the renew request..."
        New-ACMECertificate $identifierRefArr -Generate -Alias $aliasCert
        Write-Verbose "Finished Generating New ACME Cert for the renew request..."
    }

    Write-Host "Submitting New ACME Cert to get Verified by LE..."
    Submit-ACMECertificate $aliasCert
    Write-Verbose "Finished Submitting New ACME Cert to get Verified by LE..."

    Write-Host "Getting the LE Cert Export to PFX..."

    $pfxPass = Get-PassfromSecureString $pfxpassSecure
       
    try{
        Update-ACMECertificate $aliasCert
        Get-ACMECertificate $aliasCert -ExportPkcs12 "$pathToPfx\$pfxName.pfx" -CertificatePassword $pfxPass -Overwrite
    }
    catch{
        Write-Host "There was an error Exporting the Certificate, please see the error below. Exiting..." -ForegroundColor Red
        $_
        Exit
    }

    $pfxPass = $null
    Write-Host "Finished grabbing the LE Cert Export to PFX..."

}

function Finish-ACMESharp{

    param(
    [string]$RGName, 
    [string]$webAppName,  
    [string]$url, 
    [string]$pathToPfx, 
    [string]$pfxName, 
    [System.Security.SecureString]$pfxpassSecure, 
    [string]$challengeType, 
    [string]$WebConfigFile, 
    [string]$dnsRRName,
    [string[]]$dnsArray,
    [string]$dnsZoneRGName
    )

    Write-Host "Adding New Cert to your Azure WebApp..."

    $pfxPass = Get-PassfromSecureString $pfxpassSecure

    New-AzureRmWebAppSSLBinding -ResourceGroupName $RGName -WebAppName $webAppName -Name $url -CertificateFilePath "$pathToPfx\$pfxName.pfx" -CertificatePassword $pfxPass
    $pfxPass,$pfxpassSecure = $null
    Write-Verbose "Finished adding New Cert to your Azure WebApp..."

    Write-Verbose "Verifying that the New Cert was applied correctly..."
    Check-CertToSite $RGName
    Write-Verbose "Verification complete, cert has been added to your site."

    Write-Verbose "Cleaning any changes made to your WebApp config be it either DNS or Web.config changes."
        
    if($challengeType -eq "http-01"){
        Clean-Http01ChallengeToSite $WebConfigFile 
    }
    elseif($challengeType -eq "dns-01"){
        if(!$dnsArray){
            Clean-Dns01ChallengeOnSite $dnsRRName $dnsZoneRGName
        }
        else{
            $d = 0
            foreach($dnsEntry in $dnsArray){
                Clean-Dns01ChallengeOnSite $dnsEntry[$d] $dnsEntry[$d+1]
                $d++
            }
        }
    }

    Write-Host "Finished cleaning your WebApp Config env, it is back to its original state."
}

############################################################
# ACMEAzure Initialization
############################################################

#Let's take care of PFX Password First and Keep it Secure
$pfxpassSecure = ConvertTo-SecureString $pfxPassword -AsPlainText -Force

#Checking to see if LE Intermediate Certs are imported into CertMgr.
Check-IntLECerts

Check-Modules

Check-ACMEParams

try{
    if (!(Get-ACMEVault)){
        Initialize-ACMEVault
    }
}
catch{
    Write-Host "There was an error checking the ACMEVAULT, please see the error below. Exiting..." -ForegroundColor Red
    $_
    Exit    
}

if(!$subID){
    Show-Menu
}
else{
    try{
        Select-AzureRmSubscription -SubscriptionId $subID
    }
    catch{
        Write-Host "Subscription ID was not valid. Exiting." -ForegroundColor Red
        Write-Host $_
        Exit
    }
}

$date = Get-Date -Format MMddyyyy

#PFX Section
if(!$pfxName){
    $pfxName = $aliasCert + "_" + ($date)
    Write-Host "No name for PFX was specified, the new name for your pfx is: $pfxName`n"
}

#Set's ACME VaultProfile, default is :sys
$env:ACMESHARP_VAULT_PROFILE = $vaultProfile
if(!([System.IO.Path]::IsPathRooted($pathToPfx))){
        Write-Host "The Path you entered is not an absolute path, the PFX Path must be an absolute path." -ForegroundColor Red
        Write-Host "Exiting..." -ForegroundColor Red
        Exit    
}
elseif(!(Test-Path $pathToPfx)){
    Write-Verbose "Path to save Pfx does not exist. Please ensure it does."
    Write-Verbose "Let's create it..."
    mkdir $pathToPfx -ErrorAction SilentlyContinue
    if(!(Test-Path $pathToPfx)){
        Write-Host "Failed creating the path to the pfx stated in the parameters. Please make sure path is valid, and try again..." -ForegroundColor Red
        Write-Host "Exiting..." -ForegroundColor Red
        Exit
    }
    else{
        Write-Host "Path to Save PFX was created successfuly."
    }
}

if($SAN){
    Write-Verbose "SAN Flag is set to on..."
    $urlArr, $webAppNameArr, $identifierRefArr, $RGNameArr, $websiteObjArr = Check-SANParams $url $webAppName $identifierRef
    $c = 0
    foreach($url in $urlArr){
        Clean-WebAppCertPool $RGNameArr[$c] $webAppNameArr[$c] $url
        $c++
    }
}
else{
    $RGName, $websiteObj = Check-AzureParams $url $webAppName
    Clean-WebAppCertPool $RGName $webAppName $url
}

if($SAN){
    Write-Output "SAN Flag is set to on, let's run through the urls and WebApps."
    $j = 0
    if($challengeType -eq "http-01"){
        foreach($url in $urlArr){
            Start-ACMESharp -url $url -webAppName $webAppNameArr[$j] -RGName $RGNameArr[$j] -websiteObj $websiteObjArr[$j] -aliasCert $aliasCert -identifierRef $identifierRefArr[$j] -renew $renew -email $email -challengeType $challengeType -date $date -index $j
            $j++
        }

        Run-CertGeneration -identifierRef $identifierRefArr -aliasCert $aliasCert -pfxName $pfxName -pathToPfx $pathToPfx -pfxpassSecure $pfxpassSecure -SAN $SAN
        Finish-ACMESharp -url $url -webAppName $webAppNameArr[$j] -RGName $RGNameArr[$j] -challengeType $challengeType -pathToPfx $pathToPfx -pfxName $pfxName -pfxpassSecure $pfxpassSecure -WebConfigFile $websiteObj
    }
    else{
        foreach($url in $urlArr){
            $dnsValuesArr = ,@(Start-ACMESharp -url $url -webAppName $webAppNameArr[$j] -RGName $RGNameArr[$j] -websiteObj $websiteObjArr[$j] -dnsZone $dnsZone -aliasCert $aliasCert -identifierRef $identifierRefArr[$j] -renew $renew -email $email -challengeType $challengeType -date $date -index $j)
            $j++
        }

        Run-CertGeneration -identifierRef $identifierRefArr -aliasCert $aliasCert -pfxName $pfxName -pathToPfx $pathToPfx -pfxpassSecure $pfxpassSecure -SAN $SAN    
        Finish-ACMESharp -url $url -webAppName $webAppNameArr[$j] -RGName $RGNameArr[$j] -challengeType $challengeType -pathToPfx $pathToPfx -pfxName $pfxName -pfxpassSecure $pfxpassSecure -dnsArray $dnsValuesArr      
    }
    
    Write-Output "Finished running ACMESharp for the SAN Urls."
}
else{
    Write-Output "Starting to run ACMESharp"
    if($challengeType -eq "http-01"){
        Start-ACMESharp -url $url -webAppName $webAppName -RGName $RGName -websiteObj $websiteObj -aliasCert $aliasCert -identifierRef $identifierRef -renew $renew -email $email -challengeType $challengeType -date $date -index 0
        Run-CertGeneration -identifierRef $identifierRef -aliasCert $aliasCert -pfxName $pfxName -pathToPfx $pathToPfx -pfxpassSecure $pfxpassSecure
        Finish-ACMESharp -RGName $RGName -webAppName $webAppName -url $url -pathToPfx $pathToPfx -pfxName $pfxName -pfxpassSecure $pfxpassSecure -challengeType $challengeType -WebConfigFile $websiteObj    
    }
    else{
        $dnsValuesArr = ,@(Start-ACMESharp -url $url -webAppName $webAppName -RGName $RGName -websiteObj $websiteObj -dnsZone $dnsZone -aliasCert $aliasCert -identifierRef $identifierRef -renew $renew -email $email -challengeType $challengeType -date $date)
        Run-CertGeneration -identifierRef $identifierRef -aliasCert $aliasCert -pfxName $pfxName -pathToPfx $pathToPfx -pfxpassSecure $pfxpassSecure
        Finish-ACMESharp -RGName $RGName -webAppName $webAppName -url $url -pathToPfx $pathToPfx -pfxName $pfxName -pfxpassSecure $pfxpassSecure -challengeType $challengeType -dnsRRName $dnsValuesArr[0] -dnsZoneRGName $dnsValuesArr[1]       
    }

    Write-Output "Finished running ACMESharp"
}

Create-LECertInfo -url $url -pathToPfx $pathToPfx -identifierRef $identifierRef -date $date -aliasCert $aliasCert -challengeType $challengeType -webAppName $webAppName -subID $subID -pfxName $pfxName -SAN $SAN

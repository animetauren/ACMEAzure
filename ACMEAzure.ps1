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
.PARAMETER subID
    Defines the Azure subscription ID, if none is set, then a menu will be displayed asking to select a sub. 
    No default value.
.NOTES
    File Name   : ACMEAzure.ps1
    Author      : Henry Robalino - henry.robalino@outlook.com - https://anmtrn.com
    Version     :1.5 - Jan 4, 2017
.EXAMPLE
    PS C:\> .\ACMEAzure.ps1 -url sample.com -webappname samplewebapp -identifierRef "sample.com" -aliasCert "certaliasname" -email sample@outlook.com -ChallengeType "http-01" -pathToPfx "C:\certlocation" -pfxName "sampleCert"
#>

param(
		[parameter(Mandatory=$true,HelpMessage='The url of your website.')][ValidateNotNullOrEmpty()]
        [String]$url,
		[parameter(Mandatory=$true, HelpMessage='The name of the WebApp where the website resides in.')][ValidateNotNullOrEmpty()]
        [String]$webAppName,
		[parameter(Mandatory=$true, HelpMessage='A unique idenifier that is referenced in the attempt to create a certificate.')][ValidateNotNullOrEmpty()]
        [String]$identifierRef,
        [parameter(Mandatory=$true, HelpMessage='The Alias of the Cert being created for this website.')][ValidateNotNullOrEmpty()]
        [String]$aliasCert,
        [parameter(Mandatory=$true, HelpMessage='Email Address associated with this Certificate.')][ValidatePattern('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$')]
        [String]$email,
        [parameter(Mandatory=$true, HelpMessage='Which ACME challenge method to use, "http-01" or "dns-01"')][ValidateSet("http-01", "dns-01")]
        [string]$challengeType,
        [parameter(Mandatory=$true, HelpMessage='Location to store LE Cert in pfx format.')][ValidateNotNullOrEmpty()]
        [String]$pathToPfx,
        [parameter(Mandatory=$false, HelpMessage='If none chosen then it will be following: aliascert_mmddyy')][ValidateNotNullOrEmpty()]
        [String]$pfxName,
        [parameter(Mandatory=$false, HelpMessage='Azure Sub ID where the WebApp lives.')][ValidateNotNullOrEmpty()]
        [String]$subID,
        [parameter(Mandatory=$false, HelpMessage='Only needed if selecting "dns-01" as Challenge Type')][ValidateNotNullOrEmpty()]
        [String]$dnsZone

)

############################################################
# ACMEAzure Initial Checks
############################################################

function Check-AzureParams{

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

    if(!(Test-Path $pathToPfx) ){
        Write-Verbose "Path to save Pfx does not exist. Please ensure it does.Exiting..."
        Exit
    }

    $script:websiteObj = Get-AzureRmWebApp -Name $webAppName
    $script:RGName = $script:websiteObj.ResourceGroup
    $websiteResourceObj = (Get-AzureRmResource -ResourceType Microsoft.Web/sites -ResourceName "$webAppName" -ResourceGroupName $script:RGName)
    $skuWebApp = $websiteResourceObj.Properties.Sku
    if(!$script:websiteObj){
        Write-Verbose "WebApp $webAppName does not exist. Exiting"
        Exit
    }
    elseif($script:websiteObj.State -ne "Running"){
        Write-Verbose "The WebApp is currently stopped, please fix and make sure WebApp state is running. Exiting..."
        Exit
    }
    elseif(($challengeType -eq "http-01") -and ($script:websiteObj.ScmSiteAlsoStopped)){
        Write-Verbose "SCM Site for the webApp: $webAppName is in the stop state, please fix before re-running. Exiting..."    
        Exit
    }
    elseif(($script:websiteObj.HostNames[0] -ne $url) -and ($script:websiteObj.HostNames[1] -ne $url)){
        Write-Verbose "This Url does not belong to this WebApp. Exiting"
        Exit
    }
    elseif(($skuWebApp -ne "Basic") -and ($skuWebApp -ne "Standard")){
        Write-Verbose "The WebApp: $webAppName does not have the right sku, it needs to be either basic or standard. Please upgrade plan and retry. Exiting..."
        Exit
    }
    else{
        $script:RGName = $script:websiteObj.ResourceGroup
        Write-Verbose "WebApp Name is Valid, meets the requirements. Grabbed Resource Group Name."
    }      
}

function Show-Menu{

     cls
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
        $subID += @(,$sub.SubscriptionId)

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
                Select-AzureRmSubscription -SubscriptionId $subID[$subSelectedEntry]
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

function Check-Modules{

    Write-Verbose "Checking if ACMESharp Module is installed..."
    if(Get-Module -ListAvailable -Name ACMESharp) {
        Import-Module -Name ACMESharp
        Write-Verbose "Module exists continuing...`n"
    }
    else{
        Write-Verbose "Module does not exist...installing Module"
        Install-Module -Name ACMESharp
        . $profile
        Import-Module -Name ACMESharp
        Write-Verbose "ACMESharp Module has been installed!`n"
    }

    Write-Verbose "Checking if AzureRM Module is installed..."
    if((Get-Module -ListAvailable -Name AzureRM.*)) {
        Write-Verbose "Module exists continuing...`n"
    }
    else{
        Write-Verbose "Module does not exist...installing Module"
        Install-Module -Name AzureRM
        . $profile
        Import-Module -Name AzureRM
        Write-Verbose "AzureRM Module has been installed!`n"
    }
}

function Check-ACMEParams{
    
    Write-Verbose "Checking ACME Params: IdentifierRef and aliasCert"
    try{
        if(Get-ACMEIdentifier | Where-Object {$_.alias -eq "$identifierRef"} ){
            Write-Verbose "There is an Identifier Reference with same name in the Vault Already and cannot be used again."
            Exit
        }
    }
    catch{
        Write-Verbose "There are no Identifiers in the vault. The error caught can safely be ignored."
    }
    Write-Verbose "Finished Checking IdentifierRef. Next checking AliasCert."
    try{
        if((Get-ACMECertificate | Where-Object {$_.Alias -eq $aliasCert})){
            Write-Verbose "$aliasCert was already used once as an Alias Cert and cannot be used again."
            Exit
        }
    }
    catch{
        Write-Verbose "There are no Alias Certs in the vault. The error caught can be safely ignored."
    }
    Write-Verbose "Finished Checking Alias Cert. ACMEParams are fine, continuing with script."
}

function Get-PassfromSecureString{

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pfxpassSecure)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    return $PlainPassword
}

############################################################
# http-01 Challenge
############################################################

function Initialize-KuduAPI{

    Write-Verbose "Initializing Kudu API"

    $creds = Invoke-AzureRmResourceAction -ResourceGroupName $script:RGName -ResourceType Microsoft.Web/sites/config -ResourceName $webAppName/publishingcredentials -Action list -ApiVersion 2015-08-01 -Force

    $username = $creds.Properties.PublishingUserName
    $password = $creds.Properties.PublishingPassword
    $script:base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))
    $script:userAgent = "powershell/1.0"
    $apiBaseUrl = "https://$($websiteObj.SiteName).scm.azurewebsites.net/api"

    Write-Verbose "Finished Initializing Kudu API"

}

function Check-WebConfig{

    Write-Verbose "Checking if WebConfig File exists..."
    try{
        $script:checkWebConfigFile = (Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -UserAgent $script:userAgent -Method GET) | where {$_.name -eq "Web.config"}
    }
    catch{
        Write-Verbose "There seems to have been an error Sending a REST request. Please see error below. Exiting..."
        $_
        Exit
    }
    #Checking if Web.config file exists and that it is not empty, if so download it, save the original file to a temp location. Then we can read and edit the web.config file if need be, while not messing up original Web.config File.
    if($script:checkWebConfigFile -and "$script:checkWebConfigFile.size -gt 0"){
        
        Write-Verbose "Web.config File located inside the WebApp Directory."
        $WebConfigFile = [xml](Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method GET)
        
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

        Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method PUT -InFile $WebConfigFile
        Write-Verbose "Web.config file created and uploaded successfuly."
    }

    Write-Verbose "Checking if web.config has static content, if not append that to web.config file"
    if(!$WebConfigFile.configuration.'system.webServer'.staticContent){
        Write-Verbose "Web.config file did not have StaticContent configured, modifying now..."
        
        #Editing the XML File 
        $xmlWC = [xml](Get-Content $WebConfigFile)

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

        Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method PUT -InFile $WebConfigFile 
        Write-Verbose "Finished adding Web.config file..."
    }
}

function Check-SCMDirStructure{

    Write-Verbose "Checking the SCM Directory..."
    
    $wellknown = Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method GET | Where-Object {$_.name -eq ".well-known"} -ErrorAction Stop

    #Checking if .well-known dir exists

    if($wellknown){
        $acmeChallenge = Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method GET | Where-Object {$_.name -eq "acme-challenge"} -ErrorAction SilentlyContinue
        if($acmeChallenge){
            ####CHECK how this works with multple files inside the dir
            $acmeChallengeName = (Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method GET).name
            Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/$acmeChallengeName" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method DELETE
        }
        else{
            Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method PUT        
        }
    }
    else{
        Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo)} -Method PUT
    }
    Write-Verbose "Finished checking SCM Directory and configuiring the file paths."
}

function Add-Http01ChallengeToSite{

    Write-Verbose "Creating Challenge File to Upload..."

    $acmeChallengeJSONFileValue = $compACMEChall.Challenges.challenge.FileContent

    $acmejsonFile = $acmeChallengeJSONFileValue.split(".")[0]

    New-Item -Path "$Env:Temp" -Name $acmejsonFile -Value $acmeChallengeJSONFileValue -Force
    $acmeChallengeFile = (Get-ChildItem -Path "$Env:Temp\$acmejsonFile")

    Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/$acmejsonFile" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method PUT -InFile $acmeChallengeFile 
    
    Write-Verbose "Finished creating and uploading challenge file to your site."

    $challengeSite = "$url/.well-known/acme-challenge/$acmejsonFile"

    return $challengeSite
}
<#
This function needs to be fixed for certain WebApp Errors.

function Check-ChallengeFile($challUrl){
    
    $challUrlResponse = Invoke-WebRequest $challUrl.ToString()
    if($challUrlResponse -eq "The page cannot be displayed because an internal server error has occurred."){
        Write-Verbose "It seems like WebApp is misbehaving again let's try to fix this."
        
    }
}
#>
function Clean-Http01ChallengeToSite {

    if($script:checkWebConfigFile){
         Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method DELETE
         $originalWebConfigFile = (Get-ChildItem -Path "$Env:Temp\OriginalWebConfig-$date\Web.config")
         Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method PUT -InFile $originalWebConfigFile
    }
    else{
         Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method DELETE  
    }
    try{
        Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method DELETE   
        Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known" -Headers @{Authorization=("Basic {0}" -f $script:base64AuthInfo); "If-Match"=("*")} -Method DELETE   
    }
    catch{
        $_
    }
}

############################################################
# dns-01 Challenge
############################################################

function Add-Dns01ChallengeToSite{
    
    Write-Verbose "Checking to see if DNS Zone exists for this WebApp and URL..."
    $dnsZoneCheck = Get-AzureRmDnsZone | Where-Object {$_.Name -eq $dnsZone}
    if(!$dnsZoneCheck){
        Write-Verbose "There are no Azure DNS Records that match Zone: $dnsZone."
        Write-Verbose "Please confirm name and try again. Exiting..."
        Exit
    }
    else{
        $script:dnsZoneRGName = $dnsZoneCheck.ResourceGroupName 
    }
    Write-Verbose "DNS Zone Record does exist for this WebApp. Continuing..."
    Write-Verbose "Creating DNS TXT Record..."
    
    #Azure DNS does not want full fqdn
    $dnsRRInfo = ($compACMEChall.Challenges | Where-Object {$_.Type -eq "dns-01"}).Challenge
    $script:dnsRRName = $dnsRRInfo.RecordName.split(".")[0] #Azure DNS does not want full fqdn
    $dnsRRValue = $dnsRRInfo.RecordValue

    $Record = New-AzureRmDnsRecordConfig -Value $dnsRRValue
    $RecordSet = New-AzureRmDnsRecordSet -Name $script:dnsRRName -RecordType TXT -ResourceGroupName $script:dnsZoneRGName -TTL 3600 -ZoneName $dnsZone -DnsRecords $Record

    Write-Verbose "Finished creating TXT Record Set on Azure DNS for $url"
}

function Clean-Dns01ChallengeOnSite{

    Remove-AzureRmDnsRecordSet -Name $script:dnsRRName -RecordType TXT -ZoneName $dnsZone -ResourceGroupName $script:dnsZoneRGName [-Force]

}

############################################################
# Gettig LE Cert, Uploading Azure WebApp and Checking Cert
############################################################

function Get-AcmeCert {

    $pfxPass = Get-PassfromSecureString
    Get-ACMECertificate $aliasCert -ExportPkcs12 "$pathToPfx\$pfxName.pfx" -CertificatePassword $pfxPass -Overwrite
    $pfxPass = $null
}

function Add-CertToSite{

    $pfxPass = Get-PassfromSecureString
    New-AzureRmWebAppSSLBinding -ResourceGroupName $script:RGName -WebAppName $webAppName -Name $url -CertificateFilePath "$pathToPfx\$pfxName.pfx" -CertificatePassword $pfxPass
    $pfxPass = $null
}

function Check-CertToSite {

    $certChecked = Get-AzureRmWebAppSSLBinding -ResourceGroupName $script:RGName -WebAppName $webAppName

    if($certChecked){
        Write-Output "All Finished! $url has been updated with the new cert!!!" 
    }
    else{
        Write-Output "********* Woops! There was an error and your website was not updated with a new Cert, please try again!*********" 
    }
}

############################################################
# ACME Functions
############################################################

function Check-ACMEIdentifierStatus{

    Write-Verbose "Updating the ACMEIdentifier and checking to see if challenge has worked..."
    if($challengeType -eq "http01" -or $challengeType -eq "http-01"){
        $identRefStatus = ((Update-ACMEIdentifier $identifierRef -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).Status
        while($identRefStatus -ne "valid"){
            sleep -Seconds 1
            $identRefStatus = ((Update-ACMEIdentifier $identifierRef -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).Status
            if($identRefStatus -eq "invalid"){
                Write-Verbose "HTTP-01 Challenge Verification has failed for the following Identifier Reference $identifierRef"
                Exit
            }
        }
    }
    else{
        $identRefStatus = ((Update-ACMEIdentifier $identifierRef -ChallengeType dns-01).Challenges | Where-Object {$_.Type -eq "dns-01"}).Status
        while($identRefStatus -ne "valid"){
            sleep -Seconds 1
            $identRefStatus = ((Update-ACMEIdentifier $identifierRef -ChallengeType dns-01).Challenges | Where-Object {$_.Type -eq "dns-01"}).Status
            if($identRefStatus -eq "invalid"){
                Write-Verbose "DNS-01 Challenge Verification has failed for the following Identifier Reference $identifierRef"
                Exit
            }
        }
    }
    Write-Verbose "Finished Updating the ACMEIdentifier..."
}

############################################################
# ACMEAzure Core
############################################################

function Start-ACMESharp{
    
    $date = Get-Date -Format MMddyyyy

    Check-AzureParams

    Check-Modules

    if(!$pfxName){
        $pfxName = $aliasCert + "_" + ($date)
    }

    if (!(Get-ACMEVault)){
        Initialize-ACMEVault
    }

    Check-ACMEParams

    New-ACMERegistration -Contacts mailto:$email -AcceptTos

    New-ACMEIdentifier -Dns $url -Alias $identifierRef

    if($challengeType -eq "http01" -or $challengeType -eq "http-01"){
        
        Initialize-KuduAPI

        $compACMEChall = Complete-ACMEChallenge $identifierRef -ChallengeType http-01 -Handler manual

        #VFS URL API
        $apiVFSBaseUrl = "https://$($websiteObj.SiteName).scm.azurewebsites.net/api/vfs"

        #Checks WebConfig to make sure json files can be added so challenge can succeed
        Check-WebConfig

        #Checks the SCM Directory making sure that the right folders exist, if not create them.
        Check-SCMDirStructure

        #Adds the challenge json to the right dir in the Azure site. 
        $challengeReturn = Add-Http01ChallengeToSite

        #Checks that Challenge is accessible. Weird Bug needs to be fixed
        #Check-ChallengeFile $challengeReturn

        #Submit the challenge to LE Server
        Submit-ACMEChallenge -IdentifierRef $identifierRef -ChallengeType http-01

    }
    else{
        $compACMEChall = Complete-ACMEChallenge $identifierRef -ChallengeType dns-01 -Handler manual
    
        #Adds the challenge json to the right dir in the Azure site. 
        Add-Dns01ChallengeToSite

        #Submit the challenge to LE Server
        Submit-ACMEChallenge $identifierRef -ChallengeType dns-01

    }

    Check-ACMEIdentifierStatus

    Write-Verbose "Generating New ACME Cert..."
    New-ACMECertificate $identifierRef -Generate -Alias $aliasCert
    Write-Verbose "Finished Generating New ACME Cert..."

    Write-Verbose "Submitting New ACME Cert to get Verified by LE..."
    Submit-ACMECertificate $aliasCert
    Write-Verbose "Finished Submitting New ACME Cert to get Verified by LE..."

    Write-Verbose "Checking to see that LE has issued Cert..."
    Update-ACMECertificate $aliasCert
    Write-Verbose "Updating the ACMEIdentifier..."

    #Enter PFX Password
    $pfxpassSecure = Read-Host -Prompt "Enter Pfx Password" -AsSecureString 

    Write-Verbose "Updating the ACMEIdentifier..."
    Get-AcmeCert
    Write-Verbose "Updating the ACMEIdentifier..."

    Write-Verbose "Adding New Cert to your Azure WebApp..."
    Add-CertToSite
    Write-Verbose "Finished adding New Cert to your Azure WebApp..."

    Write-Verbose "Verifying that the New Cert was applied correctly..."
    Check-CertToSite
    Write-Verbose "Verification complete, cert has been added to your site."

    Write-Verbose "Cleaning any changes made to your WebApp config be it either DNS or Web.config changes."
    if($challengeType -eq "http01" -or $challengeType -eq "http-01"){
        Clean-Http01ChallengeToSite
    }
    else{
        Clean-Dns01ChallengeOnSite
    }
    Write-Verbose "Finished cleaning your WebApp Env, it is back to its original state."
}

if(!$subID){
    Show-Menu
}
else{
    try{
        Select-AzureRmSubscription -SubscriptionId $subID
    }
    catch{
        Write-Verbose "Subscription ID was not valid. Exiting."
        Write-Output $_
        Exit
    }
}

Start-ACMESharp

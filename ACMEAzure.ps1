<#
.SYNOPSIS
    ACMEAzure.ps1 - Automate the task of using the ACMESharp Library to request, validate, receive and upload Let's Encrypt Certs to Azure WebApps.
.DESCRIPTION
    Using the ACMESharp Library, automate the procedure of requesting, submitting a challenge and getting a Let's Encrypt Cert, while using Kudu API to automatically create challenged, and then upload to Azure WebApp the latest valid updated certs from LE.
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
.PARAMETER domain
    Defines the domain of the website url. 
    Mandatory parameter
.PARAMETER AliasCert
    Defines the alias of the cert that will be used by the website.
    Mandatory parameter
    No default value.
.PARAMETER email
    Defines the email used to register the new Let's Encrypt SSL
    Mandatory parameter
    No default Value.
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
.EXAMPLE
    PS C:\> .\ACMEAzure.ps1 -url sample.com -webappname samplewebapp -domain "sample.com" -AliasCert "certaliasname" -email sample@outlook.com -pathToPfx "C:\certlocation" -pfxName "sampleCert"
#>

param(
		[parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$url,
		[parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$webAppName,
		[parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$domain,
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$AliasCert,
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$email,
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$pathToPfx,
        [parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
        [String]$pfxName,
        [parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
        [String]$subID

)

function Check-Params{

    $urlMod = "http://"+$url
	try
	{
		$request = [System.Net.WebRequest]::Create($urlMod)
		$request.Method = 'HEAD'
		$response = $request.GetResponse()
		$httpStatus = $response.StatusCode
		$urlIsValid = ($httpStatus -eq 'OK')
		$response.Close()
	}
	catch [System.Exception] {
		$httpStatus = $null
		Write-Verbose "URL Parameter is not correct. Exiting"
        	Write-Verbose $_
        	Exit
	}

    if(!(Test-Path $pathToPfx) ){
        Write-Verbose "Path to save Pfx does not exist. Please ensure it does."
        Exit
    }

    $EmailRegex = '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$';
    if ($email -notmatch $EmailRegex) {
        Write-Verbose "Email Format was not correct. Please try again."
        Exit
    }

}

function Show-Menu{
     cls
     Write-Host "================ Select Subscription ================"
     $allSub = (Get-AzureRmSubscription -ErrorAction SilentlyContinue)
     if(!$allSub){
        Exit
     }

     $i = 1
     Foreach($sub in $allSub){
        $subName = @(,$sub.SubscriptionName)
        $subID += @(,$sub.SubscriptionId)

        Write-Host "$($i): Press '$i' for $subName"
        $i++
     }
     Write-Host "Q: Press 'Q' to quit."
     $input = Read-Host
     $subName
     if($input -ne "q"){
        Select-AzureRmSubscription -SubscriptionId $subID[$input-1] 
     }
     else{
        Write-Verbose "Exiting Azure Subscription Login"
        Exit
     } 
     $i = $null     

}

#Check ACMESharp Module is installed.
function Check-ACMEModule{

    Write-Verbose "Checking if ACMESharp Module is installed..."
    if (Get-Module -ListAvailable -Name ACMESharp) {
        Import-Module -Name ACMESharp
        Write-Verbose "Module exists continuing...`n"
    } else {
        Write-Verbose "Module does not exist...installing Module"
        Install-Module -Name ACMESharp
        . $profile
        Import-Module -Name ACMESharp
        Write-Verbose "ACMESharp Module has been installed!`n"
    }
}

function Initialize-KuduAPI{
Write-Verbose "************[ARM Mode]************`n"
    try{
        if(!$RGName){
            $websiteObj = Get-AzureRmWebApp -Name $webAppName
            $RGName = $websiteObj.ResourceGroup
        }
        else{
            $websiteObj = Get-AzureRmWebApp -ResourceGroupName $RGName -Name $webAppName
        }
    }
    catch{
        Write-Verbose $_
        Write-Verbose "WebApp Name was typed in wrong. Exiting"
        Exit
    }

    $creds = Invoke-AzureRmResourceAction -ResourceGroupName $RGName -ResourceType Microsoft.Web/sites/config -ResourceName $webAppName/publishingcredentials -Action list -ApiVersion 2015-08-01 -Force

    $username = $creds.Properties.PublishingUserName
    $password = $creds.Properties.PublishingPassword
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))

    $apiBaseUrl = "https://$($websiteObj.SiteName).scm.azurewebsites.net/api"

    $kuduVersion = Invoke-RestMethod -Uri "$apiBaseUrl/environment" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method GET

    #Enter PFX Password
    $pfxpassSecure = Read-Host -Prompt "Enter Pfx Password" -AsSecureString 

}

function Get-PassfromSecureString{

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pfxpassSecure)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    return $PlainPassword
}

<#
function Check-ACMEVault{
    Write-Verbose "Checking Vault to see if old profile exists..."
    $vaultLoc = @((Get-ACMEVaultProfile).VaultParameters.Values)[0]
    Write-Verbose "Vault Location is the following: $vaultLoc"
    
    if((ls $vaultLoc).Count -ne 0){
        Write-Verbose "Old Vault Profile exists, deleting it..."
        rm -r $vaultLoc
        Write-Verbose "Deleted"
    }
}
#>

function Check-SCMDirStructure{

    Write-Verbose "Checking the SCM Directory..."

    $wellknown = Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method GET | Where-Object {$_.name -eq ".well-known"} -ErrorAction SilentlyContinue

    #Checking if .well-known dir exists

    if($wellknown){
        $acmeChallenge = Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method GET | Where-Object {$_.name -eq "acme-challenge"} -ErrorAction SilentlyContinue
        if($acmeChallenge){
            ####CHECK how this works with multple files inside the dir
            $acmeChallengeName = (Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method GET).name
            Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/$acmeChallengeName" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo); "If-Match"=("*")} -Method DELETE
        }
        else{
            Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method PUT        
        }
    }
    else{
        Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method PUT
    }

}

function Check-WebConfig{

    Write-Verbose "Checking if WebConfig File exists..."

    $checkWebConfigFile = (Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method GET) | where {$_.name -eq "Web.config"}

    #Checking if Web.config file exists, if not create it and add it to the right location
    if($checkWebConfigFile -eq $null){
    
        Write-Verbose "No Web.config File was located inside your wwwroot directory."
        Write-Verbose "Creating Web.config File inside your wwwroot directory this will just allow hosting of json files without extension."
        Write-Verbose "This is necessary to complete the manual http-1 challenge."
        Write-Verbose "This will not modify or add any other access rules to your wwwroot web.config file"

$WebConfigFile = @'
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

        $WebConfigFile | Out-File "$Env:Temp\Web.config"

        $WebConfigFile = Get-Item -Path "$Env:Temp\Web.config"

        Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/$webConfigFile" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo); "If-Match"=("*")} -Method PUT

    }
    #Else read web.config file and append if stuff does not exist
    else{
        $WebConfigFile = Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/Web.config" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method GET
    }
    #Checking if web,config has static content, if not append that to web.config file
    if($webConfigFile.configuration.'system.webServer'.staticContent -eq $null){
        
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
    }
}

function Add-ChallengeToSite{

    Write-Verbose "Creating Challenge File to Upload..."

    $acmeChallengeJSONFileValue = $compACMEChall.Challenges.challenge.FileContent

    $acmejsonFile = $acmeChallengeJSONFileValue.split(".")[0]

    New-Item -Path "$Env:Temp" -Name $acmejsonFile -Value $acmeChallengeJSONFileValue
    $acmeChallengeFile = (Get-ChildItem -Path "$Env:Temp\$acmejsonFile")

    Invoke-RestMethod -Uri "$apiVFSBaseUrl/site/wwwroot/.well-known/acme-challenge/$acmejsonFile" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo); "If-Match"=("*")} -Method PUT -InFile $acmeChallengeFile 
    
    Write-Verbose "Finished creating and uploading challenge file to your site."
}

function Get-AcmeCert {

    $pfxPass = Get-PassfromSecureString
    Get-ACMECertificate $AliasCert -ExportPkcs12 "$pathToPfx\$pfxName.pfx" -CertificatePassword $pfxPass -Overwrite
    $pfxPass = $null
}

function Add-CertToSite{

    $pfxPass = Get-PassfromSecureString
    New-AzureRmWebAppSSLBinding -ResourceGroupName $RGName -WebAppName $webAppName -Name $url -CertificateFilePath "$pathToPfx\$pfxName.pfx" -CertificatePassword $pfxPass
    $pfxPass = $null
}

function Check-CertToSite {

    $certChecked = Get-AzureRmWebAppSSLBinding -ResourceGroupName $RGName -WebAppName $webAppName

    if($certChecked){
        Write-Host "All Finished! $url has been updated with the new cert!!!" -ForegroundColor Green
    }
    else{
        Write-Host "********* Woops! There was an error and your website was not updated with a new Cert, please try again!*********" -ForegroundColor Red
    }
}

function Start-ACMESharp{

Check-Params

Check-ACMEModule

Initialize-KuduAPI

if(!$pfxName){
    $pfxName = $AliasCert + "_" + (Get-Date -format M_d_yyyy)
}

#Check-ACMEVault

if (!(Get-ACMEVault))
{
    Initialize-ACMEVault
}

New-ACMERegistration -Contacts mailto:$email -AcceptTos

New-ACMEIdentifier -Dns $url -Alias $domain

$compACMEChall = Complete-ACMEChallenge $domain -ChallengeType http-01 -Handler manual

#VFS URL API
$apiVFSBaseUrl = "https://$($websiteObj.Name).scm.azurewebsites.net/api/vfs"

#Checks WebConfig to make sure json files can be added so challenge can succeed
Check-WebConfig

#Checks the SCM Directory making sure that the right folders exist, if not create them.
Check-SCMDirStructure

#Adds the challenge json to the right dir in the Azure site. 
Add-ChallengeToSite

#Submit the challenge to LE Server
Submit-ACMEChallenge $domain -ChallengeType http-01

Update-ACMEIdentifier $domain

Get-ACMEIdentifier

New-ACMECertificate $domain -Generate -Alias $AliasCert

Submit-ACMECertificate $AliasCert

Update-ACMECertificate $AliasCert

Get-AcmeCert

Add-CertToSite

Check-CertToSite

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
        Write-Host $_
        Exit
    }
}

Start-ACMESharp

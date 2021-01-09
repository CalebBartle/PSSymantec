Function Get-SEPToken {
    <#
    .SYNOPSIS
    Generates a token that is used for the Symantec Console authentication process
    This requires the username, password (and domain if used).
    
    .DESCRIPTION
    Long description
    
    .EXAMPLE
    Get-SEPToken
    #>
    function Skip-Cert {
<#
.DESCRIPTION
This function allows skipping the SSL/TLS Secure channel check in the event that there is not a valid certificate available

.EXAMPLE
Skip-Cert
#>
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()
}
function Get-RestError($Error) {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if ($Error.Exception.Response) {  
            $Reader = New-Object System.IO.StreamReader($Error.Exception.Response.GetResponseStream())
            $Reader.BaseStream.Position = 0
            $Reader.DiscardBufferedData()
            $ResponseBody = $Reader.ReadToEnd()
            if ($ResponseBody.StartsWith('{')) {
                $ResponseBody = $ResponseBody | ConvertFrom-Json
            }
            return $ResponseBody
        }
    }
    else {
        return $Error.ErrorDetails.Message
    }
}
    if($null -eq $BaseURL){
        "Please enter your symantec server's name and port."
        "(e.g. <sepservername>:8446)"
        $ServerAddress = Read-Host -Prompt "Value"
        $Global:BaseURL = "https://" + $ServerAddress + '/sepm/api/v1'
    }
    $Creds = Get-Credential
    $body =@{
        "username" = $Creds.UserName
        "password" = ([System.Net.NetworkCredential]::new("", $Creds.Password).Password)
        "domain" = ""
    }
    if($null -ne $body){
        $URI = $BaseURL + '/identity/authenticate'
        try{
            Invoke-WebRequest $BaseURL
        }
        catch{
            'SSL Certificate test failed, skipping certificate validation. Please check your certificate settings and verify this is a legitimate source.'
            $Response = Read-Host -Prompt 'Please press enter to ignore this and continue without SSL/TLS secure channel'
            if($Response -eq ""){
                Skip-Cert
            }
        }
        try{
            $SEPToken = (Invoke-RestMethod -Method POST -Uri $URI -ContentType "application/json" -Body ($body | ConvertTo-Json)).token
        }
        catch{
            "An error was found with this command. Please review the resultant error for details."
            $RESTError = Get-RestError($_)
            "Errors: $RESTError"
        }
    }
    $global:headers =@{
        "Authorization" = "Bearer $SEPToken"
        "Content" = 'application/json'
    }
}
Function Get-SEPComputers{
    <#
    .SYNOPSIS
    Displays a short or specific list of computers and their information from the Symantec Database
    .PARAMETER ComputerName
    Specifies the computer to return information on from the Symantec Database
    
    .EXAMPLE
    Get-SEPComputers -ComputerName TESTPC OR
    Get-SEPComputers
    
    .NOTES
    General notes
    #>
    [CmdletBinding()]
    Param (
    [Parameter()][ValidateNotNullOrEmpty()][String]$ComputerName
    )
    if($null -ne $headers){
        if($null -ne $ComputerName){
            $URI = $BaseURL + "/computers?computerName=$ComputerName"
            try{
                (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).content
            }catch{
                "An error was found with this command. Please review the resultant error for details."
                $RESTError = Get-RestError($_)
                "Errors: $RESTError"
            }
        } else{
            $URI = $BaseURL + '/computers'
            try{
                (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).content
            }catch{
                "An error was found with this command. Please review the resultant error for details."
                $RESTError = Get-RestError($_)
                "Errors: $RESTError"
            }
        }
    }
    if($null -eq $headers){
        Get-SEPToken
        if($null -ne $headers){
            if($null -ne $ComputerName){
                $URI = $BaseURL + "/computers?computerName=$ComputerName"
                try{
                    (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).content
                }catch{
                    "An error was found with this command. Please review the resultant error for details."
                    $RESTError = Get-RestError($_)
                    "Errors: $RESTError"
                }
            } else{
                $URI = $BaseURL + '/computers'
                try{
                    (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).content
                }catch{
                    "An error was found with this command. Please review the resultant error for details."
                    $RESTError = Get-RestError($_)
                    "Errors: $RESTError"
                }
            }
        }
    }
}
function Start-SEPScan {
    [CmdletBinding()]
    Param (
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][String]$ComputerName,
    [Parameter(Mandatory)][ValidateSet('fullscan','activescan')][String[]]$ScanType
    )
    $ComputerID = (Get-SEPComputers -ComputerName $ComputerName).uniqueId
    $URI = $BaseURL + ("/command-queue/") + [string]$ScanType + "?computer_ids=" + $ComputerID
    try{
        $Result = (Invoke-RestMethod -Method POST -Uri $URI -Headers $headers)
        if($null -ne $Result){
            "Scan Type: $ScanType, was successfully sent for: $ComputerName"
            $Result
        }
    }catch{
        "An error was found with this command. Please review the resultant error for details."
        $RESTError = Get-RestError($_)
        "Errors: $RESTError"
    }
}
function Set-SEPQuarantine {
    [CmdletBinding()]
    Param (
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][String]$ComputerName,
    [Parameter(Mandatory)][ValidateSet('true','false')][String[]]$Disabled
    )
    $ComputerID = (Get-SEPComputers -ComputerName $ComputerName).uniqueId
    $URI = $BaseURL + ("/command-queue/quarantine") + "?computer_ids=" + $ComputerID + "&undo=" + $Disabled
    try{
        $Result = (Invoke-RestMethod -Method POST -Uri $URI -Headers $headers)
        if($null -ne $Result){
            "Quarantine Disabled: $Disabled, was successfully set for: $ComputerName"
            $Result
        }
    }catch{
        "An error was found with this command. Please review the resultant error for details."
        $RESTError = Get-RestError($_)
        "Errors: $RESTError"
    }
}
Function Get-SEPAdmins{
<#
.SYNOPSIS
Displays a list of admins in the Symantec Database
.EXAMPLE
Get-SEPAdmins

.PARAMETER AdminName
Displays only a specific user from the Admin List
Get-SEPAdmins -AdminName admin

.EXAMPLE
Get-SEPAdmins

.NOTES
General notes
#>
    [CmdletBinding()]
    Param (
    [Parameter()][String]$AdminName
    )
    if($null -ne $headers){
        $URI = $BaseURL + "/admin-users"
        try{
            $admins = (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers)
            if($AdminName -eq ""){
                $admins
            }
            if("" -ne $AdminName){
                $admins  | Where-Object { $_.loginName -eq $AdminName }
            }
        }catch{
            "An error was found with this command. Please review the resultant error for details."
            $RESTError = Get-RestError($_)
            "Errors: $RESTError"
        }
    }
    if($null -eq $headers){
        Get-SEPToken
        if($null -ne $headers){
            $URI = $BaseURL + "/admin-users"
            try{
                $admins = (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers)
                if($AdminName -eq ""){
                    $admins
                }
                if("" -ne $AdminName){
                    $admins  | Where-Object { $_.loginName -eq $AdminName }
                }
            }catch{
                "An error was found with this command. Please review the resultant error for details."
                $RESTError = Get-RestError($_)
                "Errors: $RESTError"
            }
        }
    }
}
Function Update-SEPClientInfo{
    [CmdletBinding()]
    Param (
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][String]$ComputerName
    )
    $ComputerID = (Get-SEPComputers -ComputerName $ComputerName).uniqueId
    $URI = $BaseURL + ("/command-queue/updatecontent?computer_ids=") + $ComputerID
    try{
        $Result = (Invoke-RestMethod -Method POST -Uri $URI -Headers $headers)
        if($null -ne $Result){
            "Client information update request to: $ComputerName sent."
            $Result
        }
    }catch{
        "An error was found with this command. Please review the resultant error for details."
        $RESTError = Get-RestError($_)
        "Errors: $RESTError"
    }
}
Function Get-SEPClientDefVersions{
if($null -ne $headers){
    $URI = $BaseURL + "/stats/client/content"
    try{
        (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).clientDefStatusList
    }catch{
        "An error was found with this command. Please review the resultant error for details."
        $RESTError = Get-RestError($_)
        "Errors: $RESTError"
    }
}
if($null -eq $headers){
    Get-SEPToken
    if($null -ne $headers){
        $URI = $BaseURL + "/stats/client/content"
        try{
            (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).clientDefStatusList
        }catch{
            "An error was found with this command. Please review the resultant error for details."
            $RESTError = Get-RestError($_)
            "Errors: $RESTError"
        }
    }
}
}
Function Get-SEPClientStatus{
    if($null -ne $headers){
        $URI = $BaseURL + "/stats/client/onlinestatus"
        try{
            (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).clientCountStatsList
        }catch{
            "An error was found with this command. Please review the resultant error for details."
            $RESTError = Get-RestError($_)
            "Errors: $RESTError"
        }
    }
    if($null -eq $headers){
        Get-SEPToken
        if($null -ne $headers){
            $URI = $BaseURL + "/stats/client/onlinestatus"
            try{
                (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).clientCountStatsList
            }catch{
                "An error was found with this command. Please review the resultant error for details."
                $RESTError = Get-RestError($_)
                "Errors: $RESTError"
            }
        }
    }
}
Function Get-SEPClientVersions{
    if($null -ne $headers){
        $URI = $BaseURL + "/stats/client/version"
        try{
            (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).clientVersionList
        }catch{
            "An error was found with this command. Please review the resultant error for details."
            $RESTError = Get-RestError($_)
            "Errors: $RESTError"
        }
    }
    if($null -eq $headers){
        Get-SEPToken
        if($null -ne $headers){
            $URI = $BaseURL + "/stats/client/version"
            try{
                (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).clientVersionList
            }catch{
                "An error was found with this command. Please review the resultant error for details."
                $RESTError = Get-RestError($_)
                "Errors: $RESTError"
            }
        }
    }
}
Function Get-SEPClientThreatStats{
    if($null -ne $headers){
        $URI = $BaseURL + "/stats/threat"
        try{
            (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).Stats
        }catch{
            "An error was found with this command. Please review the resultant error for details."
            $RESTError = Get-RestError($_)
            "Errors: $RESTError"
        }
    }
    if($null -eq $headers){
        Get-SEPToken
        if($null -ne $headers){
            $URI = $BaseURL + "/stats/threat"
            try{
                (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).Stats
            }catch{
                "An error was found with this command. Please review the resultant error for details."
                $RESTError = Get-RestError($_)
                "Errors: $RESTError"
            }
        }
    }
}
Function Get-SEPMVersion{
    if($null -ne $headers){
        $URI = $BaseURL + "/version"
        try{
            (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers)
        }catch{
            "An error was found with this command. Please review the resultant error for details."
            $RESTError = Get-RestError($_)
            "Errors: $RESTError"
        }
    }
    if($null -eq $headers){
        Get-SEPToken
        if($null -ne $headers){
            $URI = $BaseURL + "/version"
            try{
                (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers)
            }catch{
                "An error was found with this command. Please review the resultant error for details."
                $RESTError = Get-RestError($_)
                "Errors: $RESTError"
            }
        }
    }
}
Function Get-SEPMFirewallPolicies{
    if($null -ne $headers){
        $URI = $BaseURL + "/policies/summary/fw"
        try{
            (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).content
        }catch{
            "An error was found with this command. Please review the resultant error for details."
            $RESTError = Get-RestError($_)
            "Errors: $RESTError"
        }
    }
    if($null -eq $headers){
        Get-SEPToken
        if($null -ne $headers){
            $URI = $BaseURL + "/policies/summary/fw"
            try{
                (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).content
            }catch{
                "An error was found with this command. Please review the resultant error for details."
                $RESTError = Get-RestError($_)
                "Errors: $RESTError"
            }
        }
    }
}
Function Get-SEPMEventInfo{
    if($null -ne $headers){
        $URI = $BaseURL + "/events/critical"
        try{
            (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).criticalEventsInfoList
        }catch{
            "An error was found with this command. Please review the resultant error for details."
            $RESTError = Get-RestError($_)
            "Errors: $RESTError"
        }
    }
    if($null -eq $headers){
        Get-SEPToken
        if($null -ne $headers){
            $URI = $BaseURL + "/events/critical"
            try{
                (Invoke-RestMethod -Method GET -Uri $URI -Headers $headers).criticalEventsInfoList
            }catch{
                "An error was found with this command. Please review the resultant error for details."
                $RESTError = Get-RestError($_)
                "Errors: $RESTError"
            }
        }
    }
}

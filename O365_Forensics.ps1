<#
Description: a PowerShell script to assist with BEC investigations

Author: Mike Dunn

Creation Date: 02/23/2023

Version: 1

Note: Requires Exchange Online Management module
#>

$Gadmin = Read-Host "Enter Global Admin Creds"
$Folder = Read-Host "Enter Folder Name for Evidence"
if(Test-Path "$env:UserProfile\Desktop\$Folder"){
        Write-Host "File Already Exists"
        $Folder = Read-Host "Enter Another Folder Name"
    }
New-Item -Path "$env:UserProfile\Desktop" -Name $Folder -ItemType Directory
Import-Module -Name ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName $Gadmin
Clear-Host

Function Single_Inbox_Triage{
    Read-Host "Enter Target Inbox E-Mail Address" | Set-Variable -Name Target -Scope global
    Read-Host "Enter User Name of Inbox for File Generation" | Set-Variable -Name UserName -Scope global
    (Get-Date).AddDays(-90).ToString("M/dd/yyyy") |Set-Variable -Name StartDate -Scope global
    Get-Date -Format M/dd/yyyy | Set-Variable -Name EndDate -Scope global

    Write-Host "Checking Mailbox Forwarding Rules"
    Get-Mailbox -Identity $Target | 
    Where-Object {($Null -ne $_.ForwardingSmtpAddress)} | 
    Select Identity,Name,ForwardingSmtpAddress | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Forward_Rules_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Mailbox Inbox Rules"
    Get-InboxRule -Mailbox $Target | 
    Where-Object {($Null -ne $_.ForwardTo) -or ($Null -ne $_.RedirectTo) -or ($Null -ne $_.ForwardAsAttachmentTo)} | 
    Select-Object Identity,Name,Enabled,ForwardAsAttachmentTo,ForwardTo,RedirectTo | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Inbox_Rules_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Transport Rules"
    Get-TransportRule | 
    Where-Object {($Null -ne $_.BlindCopyTo)} | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Transport_Rules_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Full Access Delegation"
    Get-Mailbox -Identity $Target | 
    Get-MailboxPermission | 
    Where-Object {($_.Accessrights -like "FullAccess")} | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\FA_Delegation_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Send As Delegation"
    Get-Mailbox -Identity $Target | 
    Get-RecipientPermission | 
    Where-Object {($_.Accessrights -like "SendAs")} | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\$Folder\SA_Delegation_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Folder Permissions"
    Get-Mailbox -Identity $Target | 
    Get-MailboxFolderPermission | 
    Where-Object {($_.user -like 'Anonymous') -or ($_.user -like 'Default') -and ($_.AccessRights -ne 'None')} |  
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Folder_Permissions_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Forwarded Mail"
    Search-UnifiedAuditLog -Operations Set-Mailbox -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Where-Object Name -eq 'forwardingsmtpaddress' | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_Forward_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Inbox Rules"
    Search-UnifiedAuditLog -Operations New-InboxRule,Set-InboxRule -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Where-Object {($_.Name -like 'ForwardTo') -or ($_.Name -eq 'RedirectTo') -or ($_.Name -eq 'ForwardAsAttachmentTo')} | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_InboxRules_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Transport Rules"
    Search-UnifiedAuditLog -Operations New-TransportRule,Set-TransportRule -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Where-Object Name -eq 'BlindCopyTo' | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_TransportRules_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Full Access Delegation"
    Search-UnifiedAuditLog -Operations Add-MailboxPermission -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Where-Object {($_.Value -eq 'FullAccess')} | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_FADelegation_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Send As Delegation"
    Search-UnifiedAuditLog -Operations Add-RecipientPermission -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Where-Object {($_.Value -eq 'SendAs')} | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_SADelegation_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Folder Permissions"
    Search-UnifiedAuditLog -Operations Add-MailboxFolderPermission,Set-MailboxFolderPermission -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Where-Object {($_.Value -like 'Anonymous') -or ($_.Value -eq 'Default')} |
    Select-Object -ExpandProperty AuditData | 
    ConvertFrom-Json | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_FolderPermissions_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Microsoft Flows"
    Search-UnifiedAuditLog -Operations CreateFlow -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json |
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_Flows_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for AutoSent Mail"
    Search-UnifiedAuditLog -Operations Send -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json |
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_Send_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for File Downloads"
    Search-UnifiedAuditLog -Operations FileDownloaded -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_FileDownload_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Role Assignment Changes"
    Search-UnifiedAuditLog -Operations New-RoleGroup,New-ManagementRoleAssignment,Set-ManagementRoleAssignment -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Where-Object {($_.Value -like 'ApplicationImpersonation')} | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_Roles_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for App Consent Grants"
    Search-UnifiedAuditLog -Operations 'Add delegated permission grant' -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json |
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_Grants_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Principal"
    Search-UnifiedAuditLog -Operations 'Add service principal' -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json |
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_Principal_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for App Role Assignment to Service Principal"
    Search-UnifiedAuditLog -Operations 'Add app role assignment to service principal' -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json |
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_AppRole_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Sharepoint Policy Changes"
    Search-UnifiedAuditLog -RecordType Sharepoint -Operations SharingPolicyChanged -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Where-Object {($_.NewValue -eq 'ExtranetWithShareByLink')} | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json | 
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_Sharepoint_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Sharepoint Anonymous Link Created"
    Search-UnifiedAuditLog -RecordType SharepointSharingOperation -Operations 'anonymouslinkcreated,anonymouslinkupdated' -UserIds $Target -StartDate $StartDate -EndDate $EndDate |
    Select-Object -ExpandProperty AuditData | 
    ConvertFrom-Json |
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_AnonLink_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Anonymous Link Used"
    Search-UnifiedAuditLog -RecordType SharepointSharingOperation -Operations 'AnonymousLinkUsed' -UserIds $Target -StartDate $StartDate -EndDate $EndDate | 
    Select-Object -ExpandProperty AuditData |
    ConvertFrom-Json |
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_AnonLinkUsed_$UserName.csv" -NoTypeInformation

    Write-Host "Checking Audit Logs for Certificates and Secrets"
    Search-UnifiedAuditLog -Operations 'Update application - Certificates and secrets management' -UserIds $Target -StartDate $StartDate -EndDate $EndDate |
    Select-Object -ExpandProperty AuditData | 
    ConvertFrom-Json |
    Export-Csv "$env:USERPROFILE\Desktop\$Folder\Audit_Cert_$UserName.csv" -NoTypeInformation

    Get-ChildItem -Path "$env:USERPROFILE\Desktop\$Folder" | 
    Where-Object {$_.Length -eq 0} | 
    Remove-Item

    Clear-Host
}

Function Single_Inbox_Audit_Logs{
    Read-Host "Enter Target Inbox E-Mail Address" | Set-Variable -Name Target -Scope global
    Read-Host "Enter Name of the Inbox User for File Generation" | Set-Variable -Name FileName -Scope global
    Set-Variable -Name OutputFile -Value "$env:UserProfile\Desktop\$Folder\Audit_Logs_$FileName.csv"
    Get-Date -Date (Get-Date -Format yyyy-MM-dd) | Set-Variable -Name Today -Scope global
    Set-Variable -Name intDays -Value 90 -Scope global
    For ($i=0; $i -le $intDays; $i++){
        For ($j=23; $j -ge 0; $j--){
            Set-Variable -Name StartDate -Value ($Today.AddDays(-$i)).AddHours($j) -Scope global
            Set-Variable -Name EndDate -Value ($Today.AddDays(-$i)).AddHours($j + 1) -Scope global
            Set-Variable -Name Audit -Value (Search-UnifiedAuditLog -UserIds $Target -StartDate $StartDate -EndDate $EndDate -ResultSize 5000) -Scope global
            Set-Variable -Name ConvertAudit -Value ($Audit | Select-Object -ExpandProperty AuditData | ConvertFrom-Json) -Scope global
            $ConvertAudit | Select-Object CreationTime,UserId,Operation,Workload,ObjectID,SiteUrl,SourceFileName,ClientIP,UserAgent,SessionId | Export-Csv $OutputFile -NoTypeInformation -Append
        Write-Host $StartDate `t $Audit.Count
        }
    }
}

Function All_Mailboxes_Triage {
    Write-Host "Checking Mailbox Forwarding Rules"
    Get-EXOMailbox -ResultSize Unlimited | 
    Where-Object {($Null -ne $_.ForwardingSmtpAddress)} | 
    Select Identity,Name,ForwardingSmtpAddress |  
    Export-Csv -Path "$env:UserProfile\Desktop\$Folder\Mailboxes_ForwardSmpt.csv"

    Write-Host "Checking Mailbox for Inbox Rules"
    Get-EXOMailbox -ResultSize Unlimited | 
    Select-Object -ExpandProperty UserPrincipalName | 
    Foreach-Object {Get-InboxRule -Mailbox $_ | 
    Select-Object -Property Identity,Name,Enabled,ForwardAsAttachmentTo,RedirectTo,ForwardTo} | 
    Export-Csv -Path "$env:UserProfile\Desktop\$Folder\Mailboxes_InboxRules.csv"

    Write-Host "Checking Mailbox for Full Access Delegation"
    Get-EXOMailbox -ResultSize Unlimited | 
    Get-EXOMailboxPermission | 
    Where-Object {($_.Accessrights -like "FullAccess")} |  
    Export-Csv -Path "$env:UserProfile\Desktop\$Folder\Mailboxes_FADelegation.csv"

    Write-Host "Checking Mailbox for Send As Delegation"
    Get-EXOMailbox -ResultSize Unlimited | 
    Get-RecipientPermission | 
    Where-Object {($_.Accessrights -like "SendAs")} |  
    Export-Csv -Path "$env:UserProfile\Desktop\$Folder\Mailboxes_SADelegation.csv"

    Write-Host "Checking Mailbox for Folder Permissions"
    Get-EXOMailbox -ResultSize Unlimited | 
    Get-EXOMailboxPermission | 
    Where-Object {($_.user -like 'Anonymous') -or ($_.user -like 'Default') -and ($_.AccessRights -ne 'None')} | 
    Export-Csv "$env:UserProfile\Desktop\$Folder\Mailboxes_FolderPermissions.csv"

    Get-ChildItem -Path "$env:USERPROFILE\Desktop\$Folder" | 
    Where-Object {$_.Length -eq 0} | 
    Remove-Item

    Clear-Host
}

Function Full_Audit_Logs{
    Set-Variable -Name OutputFile -Value "$env:UserProfile\Desktop\$Folder\All_Audit_Logs.csv" -Scope global
    Get-Date -Date (Get-Date -Format yyyy-MM-dd) | Set-Variable -Name Today -Scope global
    Set-Variable -Name intDays -Value 90 -Scope global
        For ($i=0; $i -le $intDays; $i++){
            For ($j=23; $j -ge 0; $j--){
                Set-Variable -Name StartDate -Value ($Today.AddDays(-$i)).AddHours($j) -Scope global
                Set-Variable -Name EndDate -Value ($Today.AddDays(-$i)).AddHours($j + 1) -Scope global
                Set-Variable -Name Audit -Value (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000) -Scope global
                Set-Variable -Name ConvertAudit -Value ($Audit | Select-Object -ExpandProperty AuditData | ConvertFrom-Json)
                $ConvertAudit | Select-Object CreationTime,UserId,Operation,Workload,ObjectID,SiteUrl,SourceFileName,ClientIP,UserAgent,SessionId | Export-Csv $OutputFile -NoTypeInformation -Append
            Write-Host $StartDate `t $Audit.Count
        }
    }
}

Function Geolocation{
    if(!(Test-Path "$env:UserProfile\Desktop\$Folder\All_Audit_Logs.csv")){
        Clear-Host
        Write-Host `t "Missing the All_Audit_Logs.csv File" -ForegroundColor Red
        Read-Host -Prompt "Hit 'Enter' to return to the Main Menu"
        Clear-Host
        Main
       }
    Clear-Host
    Write-Host "Gathering IP Addresses and Locations"
    Set-Variable -Name file -Value "$env:UserProfile\Desktop\$Folder\All_Audit_Logs.csv" -Scope global
    Set-Variable -Name content -Value (Get-Content $file -Raw) -Scope global
    Set-Variable -Name ipAddresses -Value ([regex]::Matches($content, "\b(?:\d{1,3}\.){3}\d{1,3}\b")) -Scope global
    ($results = $ipAddresses | Sort-Object | Get-Unique).value |
    Out-File -FilePath "$env:UserProfile\Desktop\$Folder\ipaddresses.txt"

    function Get-IPGeolocation {
        Param
        (
            [string]$IPAddress
        ) 
    Set-Variable -Name request -Value (Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$IPAddress") -Scope global
        [PSCustomObject]@{
            IP      = $request.query
            City    = $request.city
            Country = $request.country
            Isp     = $request.isp
  }
}
    Set-Variable -Name OutputFile -Value "$env:UserProfile\Desktop\$Folder\IP_GeoLocation.csv" -Scope global
    Set-Variable -Name i -Value 0 -Scope global
    Set-Variable -Name IPs -Value (Get-Content "$env:UserProfile\Desktop\$Folder\ipaddresses.txt") -Scope global
        ForEach ($IP In $IPs) {
            $i++    
                If ($i -gt 40) {
                    Write-Host "avoiding IP blocking, Sleeping for 70 seconds" 
                    Start-Sleep 70
                    $i = 0
  }
    Get-IPGeolocation($IP) | Select-Object IP, City, Country, Isp | Export-Csv $OutputFile -NoTypeInformation -Append
}
        if (Test-Path "$env:UserProfile\Desktop\$Folder\IP_GeoLocation.csv"){
            Write-Host "File has been created successfully"
        }else{
            Write-Host "File was not created successfully"
  }
    Read-Host -Prompt "Hit 'Enter' to return to the Main Menu"
    Clear-Host
}


Function Main{
Write-Host `t "________   _____  _____.__               ________   ________.________" -ForeGroundColor Green
Write-Host `t "\_____  \_/ ____\/ ____\__| ____  ____   \_____  \ /  _____/|   ____/" -ForeGroundColor Green
Write-Host `t " /   |   \   __\\   __\|  |/ ___\/ __ \    _(__  </   __  \ |____  \" -ForeGroundColor Green 
Write-Host `t "/    |    \  |   |  |  |  \  \__\  ___/   /       \  |__\  \/       \" -ForeGroundColor Green
Write-Host `t "\_______  /__|   |__|  |__|\___  >___  > /______  /\_____  /______  /" -ForeGroundColor Green
Write-Host `t "        \/                     \/    \/         \/       \/       \/" -ForeGroundColor Green 
Write-Host `t "___________                                .__" -ForeGroundColor Green                       
Write-Host `t "\_   _____/__________   ____   ____   _____|__| ____   ______" -ForeGroundColor Green        
Write-Host `t " |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\ /  ___/" -ForeGroundColor Green        
Write-Host `t " |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ \___ \" -ForeGroundColor Green         
Write-Host `t " \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  >" -ForeGroundColor Green        
Write-Host `t "     \/                    \/     \/     \/        \/     \/" -ForeGroundColor Green

Write-Host "1. Single Inbox - Triage"
Write-Host "2. Single Inbox - Audit Logs"
Write-Host "3. All Mailboxes - Triage"
Write-Host "4. All Audit Logs"
Write-Host "5. Geolocation (Requires: CSV File All_Audit_Logs)"
Write-Host "6. Quit"


$choice = Read-Host "Which option would you like to choose?"

switch($choice){
        '1' {Single_Inbox_Triage ; Main}
        '2' {Single_Inbox_Audit_Logs ; Main}
        '3' {All_Mailboxes_Triage ; Main}
        '4' {Full_Audit_Logs ; Main}
        '5' {Geolocation ; Main}
        '6' {Disconnect-ExchangeOnline}
        default {Clear-Host ; Write-Host `t "Must Choose a Number to Proceed" -ForeGroundColor Red ; Main}
    }
}

Main
# Useful IR Commands
Useful Powershell commands I use during IR triage 


**Traverse filesystem**

```powershell
Get-ChildItem [file] | Format-List *
```

**Get file metadata** 

```powershell
Get-ItemProperty C:\Test\Weather.xls | Format-List
```

**Get the value name and data of a registry entry in a registry subkey**

```powershell
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name "ProgramFilesDir"
```

**Delete Registry Key** 

```powershell
Remove-Item -Path "HKLM:\Path\To\Registry\Key" -Recurse
```

**Read registry key** 

```
Get-ChildItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\'

Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe'
```

```
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
```

Generate hash from file

```powershell
Get-FileHash
```

**Find large files using Powershell**

```
gci -r| sort -descending -property length | select -first 10 name, length, directory
```

```powershell
Get-LocalUser | Select *
```

**Files created or modified between two dates**

```powershell
Get-ChildItem -Path "C:\Path\to\folder" -Recurse | Where-Object {($_.CreationTime -ge (Get-Date "2023-06-11")) -and ($_.CreationTime -le (Get-Date "2023-06-22")) -or ($_.LastWriteTime -ge (Get-Date "2023-06-11")) -and ($_.LastWriteTime -le (Get-Date "2023-06-22"))} | Select-Object FullName, CreationTime, LastWriteTime
```

**Login history** 

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625} | Select-Object TimeCreated, Id, Message
```

**Copy file**

```powershell
Copy-Item -Source \\server\share\file -Destination C:\path\
```

**Search for file by hash** 

```
Get-ChildItem -Path C:\ -Recurse -File | Get-FileHash | Where-Object Hash -eq 'HASH_VALUE' | Select-Object Path
```

**Search for file by name**

```powershell
Get-ChildItem -Path "C:\Path\To\Search" -Filter "FileName"

 
Get-ChildItem -Path C:\Users\ -Include *.kdbx* -File -ErrorAction SilentlyContinue -Recurse
```

**File changed in last 24 hours** 

```
Get-ChildItem -Path C:\ -Recurse -File -Force | Where-Object { $_.LastWriteTime -ge (Get-Date).AddHours(-6) }
```

**Files created in last 24 hours** 

```
Get-ChildItem -Path C:\ -Recurse -File -Force | Where-Object { $_.CreationTime -ge (Get-Date).AddHours(-6) }
```

**Obtain list of all files**

```
tree C:\ /F > output.txt
dir C:\ /A:H /-C /Q /R /S /X
```

**Search Sysmon logs** 

```
Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=1} | Where-Object {$_.Properties[20].Value -like "*rdpclip*"} |fl
```

**Event logs event logs search**

```
Get-WinEvent -FilterHashtable @{ LogName='Security';} | Select Timecreated,LogName,Message | where {$_.message -like "*blah*"} |FL
```

```powershell
Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 4720} | Select-Object -Property Source, EventID, InstanceId, Message

```

**Convert evtx to csv**

```
Get-WinEvent -Path .\Microsoft-Windows-Sysmon%4Operational.evtx | Export-CSV foo.csv
```

**Split by value**

```powershell

gc .\top-1m.csv |select -First 10000 | ForEach-Object {
>>     $_.split(",")[1]
>> } | Out-File -FilePath top10k
```

**Recursively count files in each folder** 

```powershell
dir -recurse |  ?{ $_.PSIsContainer } | %{ Write-Host $_.FullName (dir $_.FullName | Measure-Object).Count }
```

**Download file from internet** 

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $env:TEMP\sysmon.zip 
```

**unzip file Powershell** 

```powershell
Expand-Archive -Path <SourcePathofZipFile> -DestinationPath <DestinationPath>
```

**Search sysmon logs** 

```
$keyword = "blah"; $logName = "Microsoft-Windows-Sysmon/Operational"; $xpathQuery = "*[System[(EventID=1)]] and *[EventData[Data and contains(.,'$keyword')]]"; Get-WinEvent -LogName $logName -FilterXPath $xpathQuery
```

To get the content of event 7045 using `Get-WinEvent`, use the following command:

```powershell
Get-WinEvent -LogName 'Security' -FilterXPath '*[System[Provider[@Name="Service Control Manager"] and (EventID="7045")]]'

Get-WinEvent -FilterHashTable @{LogName='System';ID='1'} | Format-List -Property *

Get-WinEvent -LogName 'System' -FilterXPath '*[System[Provider[@Name="Service Control Manager"] and (EventID="7045")]]' | Select-Object -First 5 | Format-List -Property *
```

**Read Eventlog with grep** 

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672} | Select-Object -First 100| Format-List -Property * | Out-String | Select-String "value"
```

To search for event ID 4672 and account name "test" using PowerShell, you can use the following command:

```
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672} | Where-Object {$_.Properties[1].Value -eq "test"} | Format-List

```

This will retrieve all events with ID 4672 in the Security log where the account name is "test".

**Get Listening Ports** 

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, OwningProcessName
```

**List running processes, parent process and path**

```powershell
Get-WmiObject -Class Win32_Process | ForEach-Object {
    $processID = $_.ProcessID
    $parentProcessID = $_.ParentProcessID
    $parentProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessID='$parentProcessID'"
    
    [PSCustomObject]@{
        ProcessName = $_.Name
        ProcessID = $processID
        ParentProcessName = $parentProcess.Name
        ExecutablePath = $_.ExecutablePath
        CommandLine = $_.CommandLine
    }
}
```

**Kill process by name** 

```powershell
Stop-Process -Name "ProcessName" -Force
```

**Generate hashes of all running processes** 

```
Get-Process | ForEach-Object {
    try {
        $hash = Get-FileHash $_.Path -Alpowershellrithm SHA256
        Write-Output "$($_.ProcessName), $hash"
    }
    catch {
        Write-Output "$($_.ProcessName), $_.Exception.Message"
    }
}
```

**List URLs visited in Firefox** 

```powershell
$historyFilePath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\places.sqlite"

$startTime = Get-Date "2022-01-01" -UFormat "%s"
$endTime = Get-Date "2022-12-31" -UFormat "%s"

$keyword = "example"

$connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection
$connection.ConnectionString = "Data Source=$historyFilePath;Version=3"
$connection.Open()

$query = @"
SELECT url
FROM moz_places
WHERE last_visit_date >= $startTime
    AND last_visit_date <= $endTime
    AND url LIKE '%$keyword%'
"@
$command = $connection.CreateCommand()
$command.CommandText = $query
```

**Upload file to forensics box** 

```powershell
$filePath = "C:\Path\To\File.txt"
$uploadUrl = "http://example.com/upload"

Invoke-RestMethod -Uri $uploadUrl -Method POST -InFile $filePath
```

**Encrypt File**

```powershell
Read-Host -Prompt "Enter the encryption passphrase" -AsSecureString | ConvertFrom-SecureString | Set-Content -Path "C:\Path\To\Your\EncryptedFile.txt”
```

**Write to event log** 

```
New-EventLog -LogName Microsoft-Windows-Sysmon/Operational -Source 'sysmontester'

Write-EventLog -LogName 'Microsoft-Windows-Sysmon/Operational' -EventID 2001 -EntryType Information -Source 'Microsoft-Windows-Sysmon' -Message 'content'
```

**Regex matching  only match sls**

```

****select-string -Path c:\temp\select-string1.txt -Pattern 'test\d' -AllMatches | % { $_.Matches } | % { $_.Value }
```

    

**Print only matching (not entire line)**

```
Get-Content .\pdf.log  | %{ [Regex]::Matches($_, "client_ip':'.*?'") } | %{ $_.Value }
```

**Translate SIDs**

```
$SID = "S-1-5-21-329068152-1454471165-1417001333-12984448" # Replace with the actual SID
$account = New-Object System.Security.Principal.SecurityIdentifier($SID)
$username = $account.Translate([System.Security.Principal.NTAccount]).Value
Write-Output $username
```

**Powershell jobs** 

```powershell
Get-ScheduledJob
```

```powershell
Get-ScheduledJob | 
Get-JobTrigger |
Ft -Property @{Label="ScheduledJob";Expression={$_.JobDefinition.Name}},ID,Enabled, At, frequency, DaysOfWeek
```

```powershell
#option one
Unregister-ScheduledTask -TaskName Christmas_Day -verbose -Confirm:$false

#option two
Unregister-ScheduledJob Christmas_Day -verbose -Confirm:$false
```

**Generate randome data**

```powershell
$fileSizeInMB = 10; $filePath = "$PWD\file.txt"; $data = [byte[]]::new($fileSizeInMB * 1MB); $random = New-Object -TypeName System.Random; $random.NextBytes($data); [System.IO.File]::WriteAllBytes($filePath, $data)
```

**Linux cut command**

```
Cut function powershell

    function cut {
    param(
        [Parameter(ValueFromPipeline=$True)] [string]$inputobject,
        [string]$delimiter='\s+',
        [string[]]$field
    )

    process {
        if ($field -eq $null) { $inputobject -split $delimiter } else {
        ($inputobject -split $delimiter)[$field] }
    }
    }
```

# Find DC list from Active Directory 


# Define time for report (default is 1 day) 
$startDate = (get-date).AddDays(-1) 

# Store successful logon events from security logs with the specified dates and workstation/IP in an array 

$slogonevents = Get-Eventlog -LogName Security -ComputerName Mo -after $startDate | where {($_.eventID -eq 4624) -or ($_.eventID -eq 4625) -or($_.eventID -eq 4634) }

# Crawl through events; print all logon history with type, date/time, status, account name, computer and IP address if user logged on remotely 

 foreach ($e in $slogonevents){ 
   # Logon Successful Events 
   # Local (Logon Type 2) 
   if (($e.EventID -eq 4624 ) -and ($e.ReplacementStrings[8] -eq 2) -and ($e.ReplacementStrings[5] -eq "Test") ){ 
     write-host "Type: Local Logon`tDate: "$e.TimeGenerated "`tStatus: Success`tUser: "$e.ReplacementStrings[5] "`tWorkstation: "$e.ReplacementStrings[11] 
   } 
  
    # Logoff Failed Events 
   # initializing logoff by user event id 4647
   if ($e.EventID -eq 4647 -and ($e.ReplacementStrings[1] -eq "Mo") ){ 
     write-host "Type: Local initiated Logoff`tDate: "$e.TimeGenerated "`tStatus: Failed`tUser: "$e.ReplacementStrings[5] "`tWorkstation: "$e.ReplacementStrings[11] 
   } 
   #successful logoff event id 4634
    if (($e.EventID -eq 4634 -and ($e.ReplacementStrings[4] -eq 2) -and ($e.ReplacementStrings[1] -eq "moham") ) ){ 
   # $e.ReplacementStrings[1]

     write-host "Type: Local initiated Logoff`tDate: "$e.TimeGenerated "`tStatus: Failed`tUser: "$e.ReplacementStrings[1] "`tWorkstation: "$e.ReplacementStrings[11] 
   } 
   
}  
 

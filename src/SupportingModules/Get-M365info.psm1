function Get-AuditdataFrom365JSON {
  <#
  .Synopsis
    This function retrieves the audit data from the JSON files in the specified directory. It has been tested with output from
    Get-M365UnifiedAuditLog (included in this module) and with the Invictus Extractor suite, since both produce the same
    one-json-object-per-line on-disk format: https://github.com/invictus-ir/Microsoft-Extractor-Suite
  .Description
    This function retrieves the audit data from the JSON files in the specified directory, and returns an array of audit events.
    It's a supporting function for the Get-M365ComplianceInfo script.
  .Inputs
    This scripts takes a single parameter, the path to the directory containing the JSON files. It does not recursively search
    through subdirectories, so ensure that files of interest are in a single directory.
  .Outputs
    An array of audit events is returned.
  #>
  [CmdletBinding()]
  param (
      #[Parameter(Mandatory = $true)]
      [string]$searchdir 
  )

  $ErrorActionPreference = "Stop"

  # Just making sure the directory is set properly
  if ($searchdir -match "^.*\\$") {
      $searchdir = $searchdir -replace "\\$",""
  }

  $jsonfiles = Get-ChildItem -Path $searchdir -Filter *.json
  Write-Host "There are $($jsonfiles.count) JSON files to process" -ForegroundColor Green
  if ($jsonfiles.count -eq 0) {
      Write-Verbose "No JSON files found, exiting"
      return @()
  }

  try {
      Write-Host "Retrieving logs from $($searchdir)" -ForegroundColor Yellow
      Write-Verbose "Invoking Get-Content $searchdir\*.json"
      $auditevents = Get-Content $searchdir\*.json | ConvertFrom-Json
      Write-Host "There are $($auditevents.count) events" -ForegroundColor Yellow
  } catch {
      Write-Host -ForegroundColor Red "There was a problem retrieving JSON files from the selected directory: $searchdir"
      Write-Host -ForegroundColor Yellow "The script does not recursively search for JSON files"
      return @()
  }

  return $auditevents
}

  function Get-M365ApplicationNameFromAppID {
    <#
    .Synopsis
      This function returns the name of the application based on the application ID from the Unified Audit Logs.

    #>
    param (
        [string]$applicationID
    )
#TODO: Grab application IDS like this:
#$apps = (Invoke-WebRequest -UseBasicParsing  https://raw.githubusercontent.com/Beercow/Azure-App-IDs/master/Azure_Application_IDs.csv).content | ConvertFrom-Csv
    switch ($applicationID) {
        "23523755-3a2b-41ca-9315-f81f3f566a95" { "ACOM Azure Website" }
        "69893ee3-dd10-4b1c-832d-4870354be3d8" { "AEM-DualAuth" }
        "7ab7862c-4c57-491e-8a45-d52a7e023983" { "App Service" }
        "0cb7b9ec-5336-483b-bc31-b15b5788de71" { "ASM Campaign Servicing" }
        "7b7531ad-5926-4f2d-8a1d-38495ad33e17" { "Azure Advanced Threat Protection" }
        "e9f49c6b-5ce5-44c8-925d-015017e9f7ad" { "Azure Data Lake" }
        "835b2a73-6e10-4aa5-a979-21dfda45231c" { "Azure Lab Services Portal" }
        "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" { "Azure Portal" }
        "37182072-3c9c-4f6a-a4b3-b3f91cacffce" { "AzureSupportCenter" }
        "9ea1ad79-fdb6-4f9a-8bc3-2b70f96e34c7" { "Bing" }
        "20a11fe0-faa8-4df5-baf2-f965f8f9972e" { "ContactsInferencingEmailProcessor" }
        "bb2a2e3a-c5e7-4f0a-88e0-8e01fd3fc1f4" { "CPIM Service" }
        "e64aa8bc-8eb4-40e2-898b-cf261a25954f" { "CRM Power BI Integration" }
        "00000007-0000-0000-c000-000000000000" { "Dataverse" }
        "60c8bde5-3167-4f92-8fdb-059f6176dc0f" { "Enterprise Roaming and Backup" }
        "497effe9-df71-4043-a8bb-14cf78c4b63b" { "Exchange Admin Center" }
        "f5eaa862-7f08-448c-9c4e-f4047d4d4521" { "FindTime" }
        "b669c6ea-1adf-453f-b8bc-6d526592b419" { "Focused Inbox" }
        "c35cb2ba-f88b-4d15-aa9d-37bd443522e1" { "GroupsRemoteApiRestClient" }
        "d9b8ec3a-1e4e-4e08-b3c2-5baf00c0fcb0" { "HxService" }
        "a57aca87-cbc0-4f3c-8b9e-dc095fdc8978" { "IAM Supportability" }
        "16aeb910-ce68-41d1-9ac3-9e1673ac9575" { "IrisSelectionFrontDoor" }
        "d73f4b35-55c9-48c7-8b10-651f6f2acb2e" { "MCAPI Authorization Prod" }
        "944f0bd1-117b-4b1c-af26-804ed95e767e" { "Media Analysis and Transformation Service" }
        "0cd196ee-71bf-4fd6-a57c-b491ffd4fb1e" { "Media Analysis and Transformation Service" }
        "ee272b19-4411-433f-8f28-5c13cb6fd407" { "Microsoft 365 Support Service" }
        "0000000c-0000-0000-c000-000000000000" { "Microsoft App Access Panel" }
        "65d91a3d-ab74-42e6-8a2f-0add61688c74" { "Microsoft Approval Management" }
        "38049638-cc2c-4cde-abe4-4479d721ed44" { "Microsoft Approval Management" }
        "29d9ed98-a469-4536-ade2-f981bc1d605e" { "Microsoft Authentication Broker" }
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46" { "Microsoft Azure CLI" }
        "1950a258-227b-4e31-a9cf-717495945fc2" { "Microsoft Azure PowerShell" }
        "0000001a-0000-0000-c000-000000000000" { "MicrosoftAzureActiveAuthn" }
        "cf36b471-5b44-428c-9ce7-313bf84528de" { "Microsoft Bing Search" }
        "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8" { "Microsoft Bing Search for Microsoft Edge" }
        "1786c5ed-9644-47b2-8aa0-7201292175b6" { "Microsoft Bing Default Search Engine" }
        "3090ab82-f1c1-4cdf-af2c-5d7a6f3e2cc7" { "Microsoft Defender for Cloud Apps" }
        "18fbca16-2224-45f6-85b0-f7bf2b39b3f3" { "Microsoft Docs" }
        "00000015-0000-0000-c000-000000000000" { "Microsoft Dynamics ERP" }
        "6253bca8-faf2-4587-8f2f-b056d80998a7" { "Microsoft Edge Insider Addons Prod" }
        "99b904fd-a1fe-455c-b86c-2f9fb1da7687" { "Microsoft Exchange ForwardSync" }
        "00000007-0000-0ff1-ce00-000000000000" { "Microsoft Exchange Online Protection" }
        "51be292c-a17e-4f17-9a7e-4b661fb16dd2" { "Microsoft Exchange ProtectedServiceHost" }
        "fb78d390-0c51-40cd-8e17-fdbfab77341b" { "Microsoft Exchange REST API" }
        "3b47dcb1-459b-44a3-8084-bf6b4e5e687d" { "Microsoft Flow" }
        "2e9c3eb1-3d4a-4edc-9e32-58a095f301f5" { "Microsoft Forms" }
        "f0a6a1a6-6f57-4ca8-97af-7ab5a73d0f0a" { "Microsoft Forms Shared" }
        "0000000b-0000-0000-c000-000000000000" { "Microsoft Intune" }
        "00000016-0000-0000-c000-000000000000" { "Microsoft Kaizala" }
        "b896ed9e-2def-44a1-bb1a-c15fec5e2982" { "Microsoft Managed Desktop" }
        "00000002-0000-0ff1-ce00-000000000000" { "Microsoft Office 365" }
        "0b3d7b21-fb8e-4848-87de-5aa1d785f054" { "Microsoft Office 365 admin portal" }
        "20a11fe0-faa8-4df5-baf2-f965f8f9972e" { "Microsoft Office 365 ProPlus" }
        "0a9b3b8f-365c-4c36-8ccd-acdb03d11a13" { "Microsoft Office Sway" }
        "00000004-0000-0ff1-ce00-000000000000" { "Microsoft Office Teams" }
        "8c7cfe75-8101-47a0-a130-1d3e5470b716" { "Microsoft Office Teams" }
        "4a3dbf5b-2e2d-4c71-9f67-4d3b2e4f524f" { "Microsoft OneDrive" }
        "00000009-0000-0ff1-ce00-000000000000" { "Microsoft OneNote" }
        "00000003-0000-0ff1-ce00-000000000000" { "Microsoft Outlook" }
        "00000006-0000-0ff1-ce00-000000000000" { "Microsoft Planner" }
        "69e1c733-8059-4e0a-9310-6a7f6b8fc808" { "Microsoft PowerApps" }
        "00000010-0000-0ff1-ce00-000000000000" { "Microsoft PowerBI" }
        "4bc8e3b0-229b-42c9-bba2-3ec9db8a48da" { "Microsoft Service Health Dashboard" }
        "00000013-0000-0ff1-ce00-000000000000" { "Microsoft SharePoint" }
        "00000014-0000-0ff1-ce00-000000000000" { "Microsoft SharePoint Online" }
        "0000000d-0000-0ff1-ce00-000000000000" { "Microsoft Stream" }
        "00000005-0000-0ff1-ce00-000000000000" { "Microsoft Sway" }
        "03e4b8c3-8fca-4c11-9abb-26926c0e726f" { "Microsoft Teams Rooms" }
        "8e35a881-0321-4b38-9873-5838ed86aa63" { "Microsoft Teams Services" }
        "aef00550-dfeb-49d5-b875-362191fffc6e" { "Microsoft Teams Services" }
        "392ec2ae-4d4a-4b6d-95b5-996b7c9a63b5" { "Microsoft Teams Services" }
        "02e975ff-d6b8-4b1a-8d2d-9e5c89e724e1" { "Microsoft Video Portal" }
        "00000017-0000-0000-c000-000000000000" { "Microsoft Whiteboard" }
        "fc4c52f4-d645-4f86-9e8b-a4f255f23c96" { "MyAnalytics" }
        "02c2d2e7-79fe-442b-8f5b-74e181ad57b4" { "Office Delve" }
        "ea1f8e8e-8d7c-4d7a-9b2f-6625ba2c9127" { "Office Graphics Service" }
        "48d688a1-35a5-45b3-86b7-18c89717ce19" { "Office Online" }
        "00000011-0000-0ff1-ce00-000000000000" { "Office Online for Consumer" }
        "87b675ff-034d-4c3c-8a02-42aa4cf52d39" { "Office Online for Education" }
        "e3bc42b6-2222-4f62-8a0b-ec9645c6cbbd" { "OneDrive for Business" }
        "96892780-e0b2-44d0-b3f7-33c3debf41f4" { "OneDrive for Business" }
        "b50e39be-8342-42c2-ba73-ccdbd75f757b" { "Outlook Online" }
        "7b94a545-7072-43e4-82a2-578d3f081b86" { "PeopleGraph" }
        "f8033783-2f9a-4a47-91d4-9b0b772b7737" { "Power Apps Portal" }
        "ff5c3ab9-6e6d-47a2-ad50-94ce76eb4e18" { "Power BI Portal" }
        "ebbd5bb5-0f49-4fd8-b36e-4a72a77af6e3" { "Power Platform" }
        "41b23d84-4dd5-44ad-aca0-4011dbb2d72d" { "Project Cortex" }
        "00000012-0000-0ff1-ce00-000000000000" { "SharePoint Home" }
        "11cd3e91-277f-4649-ba77-f9841d4f3030" { "SharePoint My Site Host" }
        "0000000a-0000-0ff1-ce00-000000000000" { "Skype for Business" }
        "0000000e-0000-0ff1-ce00-000000000000" { "Sway" }
        "61e0919e-c63b-4b83-9671-4d0e0833f83d" { "Teams Calling Web" }
        "8aa7412e-537d-41e8-8b4d-2468e317ca90" { "Teams Devices" }
        "288ebdaf-4ee4-47a0-bb24-770c7698bd6b" { "Teams Meeting Broadcast" }
        "c9d127e0-4677-4ba4-8a92-d10a1c3c8391" { "Teams Services" }
        "a76834df-6017-41ea-a7fb-df5a42dfdbe5" { "Teams Services" }
        "b2da3f06-6f74-4690-9d7d-53f5645b21d5" { "Teams Services" }
        "2e1174db-1799-403d-a204-580a9f78c4b6" { "Transcription" }
        "bd338d5d-74e2-48b9-900a-5572c773e398" { "Universal Print" }
        "00000008-0000-0ff1-ce00-000000000000" { "Word Online" }
        "00000018-0000-0000-c000-000000000000" { "Yammer" }
        "de8bc8b5-d9f9-48b1-a8ad-b748da725064" { "Graph Explorer" }
        "14d82eec-204b-4c2f-b7e8-296a70dab67e" { "Microsoft Graph Command Line Tools" }
        "7ae974c5-1af7-4923-af3a-fb1fd14dcb7e" { "OutlookUserSettingsConsumer" }
        "5572c4c0-d078-44ce-b81c-6cbf8d3ed39e" { "Vortex [wsfed enabled]" }
        "00000002-0000-0ff1-ce00-000000000000" { "Office 365 Exchange Online" }
        default { "Unknown Application" }
    }
  }
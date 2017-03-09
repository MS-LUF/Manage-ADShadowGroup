#
# Created by: lucas.cueff[at]lucas-cueff.com
#
# Released on: 02/2017
#
#'(c) 2017 lucas-cueff.com - Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'
#
<#
	.SYNOPSIS 
	Help managing Active Directory ShadowGroup (create, add member, remove...)

	.DESCRIPTION
	Manage-ADShadowGroup.psm1 module help admins to manage AD Shadow Group object in an Active Directory environment.
	Require a 2016 Active Directory with "Privileged Access Management Feature" to be used.
	Require RSAT if used on non Domain Controller environment.

	.NOTE
	https://support.microsoft.com/en-us/help/3155495/you-can-t-use-the-active-directory-shadow-principal-groups-feature-for-groups-that-are-always-filtered-out-in-windows
	https://msdn.microsoft.com/en-us/library/mt220488.aspx
	https://msdn.microsoft.com/en-us/library/mt220162.aspx
	
	.EXAMPLE
	C:\PS> import-module Manage-ADShadowGroup.psm1
#>

# begin functions
Function Get-ADShadowGroup { 
	[CmdletBinding()] 
	Param( 
		  [parameter(Mandatory=$True)] 
		  [String]$GroupNameValue
		  ) 
<#
	.SYNOPSIS 
	Get properties of an AD ShadowGroup, including members

	.DESCRIPTION
	Get properties of an AD ShadowGroup, including members

	.PARAMETER GroupNameValue
	Mandatory parameter
	-GroupNameValue string
	Provide Shadow Group name to search in configuration partition of directory (cn=Shadow Principal Configuration,cn=Services...) (object to be searched only in the current AD)
	
	.NOTE
	TTL value could not be shown if set due to Microsoft limitation (not managed at this time, even if the query is made directly in LDAP)

	.OUTPUTS
	TypeName: Microsoft.ActiveDirectory.Management.ADObject
	
	CanonicalName                   : admin.ad/Configuration/Services/Shadow Principal Configuration/PROD-Domain Admins
	CN                              : PROD-Domain Admins
	Created                         : 08/03/2017 16:00:41
	createTimeStamp                 : 08/03/2017 16:00:41
	Deleted                         :
	Description                     :
	DisplayName                     :
	DistinguishedName               : CN=PROD-Domain Admins,CN=Shadow Principal
									  Configuration,CN=Services,CN=Configuration,DC=admin,DC=ad
	dSCorePropagationData           : {01/01/1601 01:00:00}
	instanceType                    : 4
	isDeleted                       :
	LastKnownParent                 :
	member                          : {CN=Temp Prod Admins Shadow,OU=Admins,DC=admin,DC=ad, CN=Temp Prod
									  Admins,OU=Admins,DC=admin,DC=ad, CN=Prod Admins,OU=Admins,DC=admin,DC=ad}
	Modified                        : 08/03/2017 19:12:47
	modifyTimeStamp                 : 08/03/2017 19:12:47
	msDS-ShadowPrincipalSid         : S-1-1-11-1111111111-1111111111-111111111-111
	Name                            : PROD-Domain Admins
	nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
	ObjectCategory                  : CN=ms-DS-Shadow-Principal,CN=Schema,CN=Configuration,DC=admin,DC=ad
	ObjectClass                     : msDS-ShadowPrincipal
	ObjectGUID                      : 37e6ba38-1787-41ef-937f-02a7c0be6fc3
	ProtectedFromAccidentalDeletion : False
	sDRightsEffective               : 11
	uSNChanged                      : 16646
	uSNCreated                      : 16442
	whenChanged                     : 08/03/2017 19:12:47
	whenCreated                     : 08/03/2017 16:00:41

	.EXAMPLE
	C:\PS> Get-ADShadowGroup -GroupNameValue "Shadow-Domain Admins"
#>
		  
	try {
		import-module ActiveDirectory
	} catch {
		Write-Host "Not able to load active directory module - KO"  -foregroundcolor "Red"
		Write-Host "Please check RSAT is installed if you are running the script on A PC"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return 
	}
	$CurrentConfigurationPartDN = ([ADSI]"LDAP://RootDSE").configurationNamingContext
	$ShadowGroupPath = "cn=Shadow Principal Configuration,cn=Services,$($CurrentConfigurationPartDN)"
	$CheckObject = get-adobject -Filter "ObjectClass -eq 'msDS-ShadowPrincipal' -and Name -eq '$($GroupNameValue)'" -SearchBase "$($ShadowGroupPath)" -properties *
	If (-not $CheckObject) {
		Write-Host "ShadowPrincipal group $($GroupNameValue) not found ! - KO"  -foregroundcolor "Red"
		return
	}
	$CheckObject
}

Function Add-ADShadowGroup {
	[CmdletBinding()]
	Param(
	  [Parameter(Mandatory=$False,Position=1)]
		[string]$GroupNameValue,
		  [Parameter(Mandatory=$False,Position=2)]
		[string]$GroupSIDValue
	)
	<#
	.SYNOPSIS 
	Create a new AD ShadowGroup

	.DESCRIPTION
	Create a new AD ShadowGroup in the default container (cn=Shadow Principal Configuration,cn=Services...) (object to be searched only in the current AD)

	.PARAMETER GroupNameValue
	Mandatory parameter
	-GroupNameValue string
	Provide Shadow Group name to be created in configuration partition of directory (cn=Shadow Principal Configuration,cn=Services...) (object to be searched only in the current AD)
	
	.PARAMETER GroupSIDValue
	Mandatory parameter
	-GroupSIDValue string
	Provide SID of another AD group or user to shadow

	.OUTPUTS
	TypeName: Microsoft.ActiveDirectory.Management.ADObject
	
	CanonicalName                   : admin.ad/Configuration/Services/Shadow Principal Configuration/PROD-Domain Admins
	CN                              : PROD-Domain Admins
	Created                         : 08/03/2017 16:00:41
	createTimeStamp                 : 08/03/2017 16:00:41
	Deleted                         :
	Description                     :
	DisplayName                     :
	DistinguishedName               : CN=PROD-Domain Admins,CN=Shadow Principal
									  Configuration,CN=Services,CN=Configuration,DC=admin,DC=ad
	dSCorePropagationData           : {01/01/1601 01:00:00}
	instanceType                    : 4
	isDeleted                       :
	LastKnownParent                 :
	member                          : {CN=Temp Prod Admins Shadow,OU=Admins,DC=admin,DC=ad, CN=Temp Prod
									  Admins,OU=Admins,DC=admin,DC=ad, CN=Prod Admins,OU=Admins,DC=admin,DC=ad}
	Modified                        : 08/03/2017 19:12:47
	modifyTimeStamp                 : 08/03/2017 19:12:47
	msDS-ShadowPrincipalSid         : S-1-1-11-1111111111-1111111111-111111111-111
	Name                            : PROD-Domain Admins
	nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
	ObjectCategory                  : CN=ms-DS-Shadow-Principal,CN=Schema,CN=Configuration,DC=admin,DC=ad
	ObjectClass                     : msDS-ShadowPrincipal
	ObjectGUID                      : 37e6ba38-1787-41ef-937f-02a7c0be6fc3
	ProtectedFromAccidentalDeletion : False
	sDRightsEffective               : 11
	uSNChanged                      : 16646
	uSNCreated                      : 16442
	whenChanged                     : 08/03/2017 19:12:47
	whenCreated                     : 08/03/2017 16:00:41

	.EXAMPLE
	C:\PS> Add-ADShadowGroup -GroupNameValue "Shadow-Domain Admins" -GroupSIDValue "S-1-1-11-1111111111-1111111111-111111111-111"
	#>
	try {
		import-module ActiveDirectory
	} catch {
		Write-Host "Not able to load active directory module - KO"  -foregroundcolor "Red"
		Write-Host "Please check RSAT is installed if you are running the script on A PC"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return 
	}
	$CurrentConfigurationPartDN = ([ADSI]"LDAP://RootDSE").configurationNamingContext
	$ShadowGroupPath = "cn=Shadow Principal Configuration,cn=Services,$($CurrentConfigurationPartDN)"
	$CheckObject = get-adobject -Filter "ObjectClass -eq 'msDS-ShadowPrincipal' -and Name -eq '$($GroupNameValue)'" -SearchBase "$($ShadowGroupPath)" -properties DistinguishedName
	If ($CheckObject) {
		Write-Host "ShadowPrincipal group $($GroupNameValue) already exists ! - KO"  -foregroundcolor "Red"
		return
	}
	If ($GroupSIDValue -match 'S-[0-9]-[0-9]-[0-9]{2}-[0-9]{10}-[0-9]{10}-[0-9]{9}-[0-9]{2,}') {
		try {
			New-ADObject -Type "msDS-ShadowPrincipal" -Name "$($GroupNameValue)" -Path "$($ShadowGroupPath)" -OtherAttributes @{'msDS-ShadowPrincipalSid'= "$($GroupSIDValue)"}
		} catch {
			Write-Host "Not able to create new ShadowPrincipal group $($GroupNameValue) for SID $($GroupSIDValue) - KO"  -foregroundcolor "Red"
			write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
			write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
			return 
		}
	} Else {
		Write-Host "provided SID not in the right format - KO"  -foregroundcolor "Red"
	}
	$CheckObject = get-adobject -Filter "ObjectClass -eq 'msDS-ShadowPrincipal' -and Name -eq '$($GroupNameValue)'" -SearchBase "$($ShadowGroupPath)" -properties *
	$CheckObject
}

function Remove-ADShadowGroup {
	[CmdletBinding()]
	Param(
	  [Parameter(Mandatory=$False,Position=1)]
		[string]$ShadowGroupToremove
	)
	try {
		import-module ActiveDirectory
	} catch {
		Write-Host "Not able to load active directory module - KO"  -foregroundcolor "Red"
		Write-Host "Please check RSAT is installed if you are running the script on A PC"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return 
	}
	<#
	.SYNOPSIS 
	Remove an existing AD ShadowGroup

	.DESCRIPTION
	Remove a existing AD ShadowGroup hosted in the default container (cn=Shadow Principal Configuration,cn=Services...) (object to be searched only in the current AD)

	.PARAMETER GroupNameValue
	Mandatory parameter
	-GroupNameValue string
	Provide Shadow Group name to be removed in configuration partition of directory (cn=Shadow Principal Configuration,cn=Services...) (object to be searched only in the current AD)
	
	.OUTPUTS
	Console write-line output
	"ShadowPrincipal group XXXX removed correctly ! - OK"

	.EXAMPLE
	C:\PS> Remove-ADShadowGroup -GroupNameValue "Shadow-Domain Admins"
	#>
	$CurrentConfigurationPartDN = ([ADSI]"LDAP://RootDSE").configurationNamingContext
	$ShadowGroupPath = "cn=Shadow Principal Configuration,cn=Services,$($CurrentConfigurationPartDN)"

	try {
		$ShadowGroups = Get-ADObject -Filter * -SearchBase "$($ShadowGroupPath)" -properties CN
	} catch {
		Write-Host "Not able to find shadow group in default container of configuration, please investigate - KO"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return
	}

	try {
		$GroupToRemove = get-adobject -Filter "ObjectClass -eq 'msDS-ShadowPrincipal' -and Name -eq '$($ShadowGroupToremove.trim())'" -SearchBase "$($ShadowGroupPath)" -properties DistinguishedName
	} catch {
		Write-Host "Not able to locate ShadowPrincipal group $($ShadowGroupToremove) - KO"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return
	}

	try {
		Remove-ADObject $GroupToRemove.distinguishedname -Confirm:$false
	} catch {
		Write-Host "Not able to remove ShadowPrincipal group $($ShadowGroupToremove) - KO"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return 
	}
	
	$CheckObject = get-adobject -Filter "ObjectClass -eq 'msDS-ShadowPrincipal' -and Name -eq '$($ShadowGroupToremove)'" -SearchBase "$($ShadowGroupPath)" -properties *
	If (-not $CheckObject) {
		Write-Host "ShadowPrincipal group $($ShadowGroupToremove) removed correctly ! - OK"  -foregroundcolor "green"
		return
	}
}

function Add-ADShadowGroupMember {
	Param(
	  [Parameter(Mandatory=$true,Position=1)]
		[string]$GroupNameValue,
	  [Parameter(Mandatory=$true,Position=2)]
		[string]$MemberNameValue,
     [parameter(Mandatory=$true,Position=3)]
     [ValidateSet("user", "group")]
        [String]$TypeValue,
	 [Parameter(Mandatory=$False,Position=4)]
		[string]$TTLValue
	)
	<#
	.SYNOPSIS 
	Add a new member in an existing AD ShadowGroup

	.DESCRIPTION
	Add a new member in an existing AD ShadowGroup. The member could be a user or a group but must be located in the same AD hosting the Shadow Group.

	.PARAMETER GroupNameValue
	Mandatory parameter
	-GroupNameValue string
	Provide Shadow Group name to be used in configuration partition of directory (cn=Shadow Principal Configuration,cn=Services...) (object to be searched only in the current AD)
	
	.PARAMETER MemberNameValue
	Mandatory parameter
	-MemberNameValue string
	Provide the name of user or group to be added in the "member" attribute of the AD Shadow Group (object to be searched only in the current AD)
	
	.PARAMETER MemberNameValue
	Mandatory parameter
	-TypeValue string (user or group)
	Provide the type of member to add (user or group) (object to be searched only in the current AD)
	
	.PARAMETER TTLValue
	Optional parameter
	-TTLValue string (time in second)
	Provide the TTL membership for the entry to be added (user or group). At the end of the TTL, the entry is removed automatically from the member attribute of the object.

	.OUTPUTS
	TypeName: Microsoft.ActiveDirectory.Management.ADObject
	
	CanonicalName                   : admin.ad/Configuration/Services/Shadow Principal Configuration/PROD-Domain Admins
	CN                              : PROD-Domain Admins
	Created                         : 08/03/2017 16:00:41
	createTimeStamp                 : 08/03/2017 16:00:41
	Deleted                         :
	Description                     :
	DisplayName                     :
	DistinguishedName               : CN=PROD-Domain Admins,CN=Shadow Principal
									  Configuration,CN=Services,CN=Configuration,DC=admin,DC=ad
	dSCorePropagationData           : {01/01/1601 01:00:00}
	instanceType                    : 4
	isDeleted                       :
	LastKnownParent                 :
	member                          : {CN=Temp Prod Admins Shadow,OU=Admins,DC=admin,DC=ad, CN=Temp Prod
									  Admins,OU=Admins,DC=admin,DC=ad, CN=Prod Admins,OU=Admins,DC=admin,DC=ad}
	Modified                        : 08/03/2017 19:12:47
	modifyTimeStamp                 : 08/03/2017 19:12:47
	msDS-ShadowPrincipalSid         : S-1-1-11-1111111111-1111111111-111111111-111
	Name                            : PROD-Domain Admins
	nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
	ObjectCategory                  : CN=ms-DS-Shadow-Principal,CN=Schema,CN=Configuration,DC=admin,DC=ad
	ObjectClass                     : msDS-ShadowPrincipal
	ObjectGUID                      : 37e6ba38-1787-41ef-937f-02a7c0be6fc3
	ProtectedFromAccidentalDeletion : False
	sDRightsEffective               : 11
	uSNChanged                      : 16646
	uSNCreated                      : 16442
	whenChanged                     : 08/03/2017 19:12:47
	whenCreated                     : 08/03/2017 16:00:41

	.EXAMPLE
	C:\PS> Add-ADShadowGroupMember -GroupNameValue "Shadow-Domain Admins" -MemberNameValue "Domain Admins" -MemberNameValue group
	
	.EXAMPLE
	C:\PS> Add-ADShadowGroupMember -GroupNameValue "Shadow-Domain Admins" -MemberNameValue "Super-Admin" -MemberNameValue user
	
	.EXAMPLE
	C:\PS> Add-ADShadowGroupMember -GroupNameValue "Shadow-Domain Admins" -MemberNameValue "Temp-Super-Admin" -MemberNameValue user -TTLValue "3600"
	#>
	try {
		import-module ActiveDirectory
	} catch {
		Write-Host "Not able to load active directory module - KO"  -foregroundcolor "Red"
		Write-Host "Please check RSAT is installed if you are running the script on A PC"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return 
	}
	$CurrentConfigurationPartDN = ([ADSI]"LDAP://RootDSE").configurationNamingContext
	$ADPArtDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
	$ShadowGroupPath = "cn=Shadow Principal Configuration,cn=Services,$($CurrentConfigurationPartDN)"
	$CheckShadowObject = get-adobject -Filter "ObjectClass -eq 'msDS-ShadowPrincipal' -and Name -eq '$($GroupNameValue)'" -SearchBase "$($ShadowGroupPath)" -properties member
	$CheckShadowObjectDN = $CheckShadowObject.DistinguishedName | select-object
	If (-not $CheckShadowObject) {
		Write-Host "ShadowPrincipal group $($GroupNameValue) not found ! - KO"  -foregroundcolor "Red"
		return
	}
	try {
		$checkUserObject = get-adobject -Filter "ObjectClass -eq '$($TypeValue)' -and cn -eq '$($MemberNameValue)'" -SearchBase "$($ADPArtDN)" -SearchScope Subtree -properties *
		$checkUserObjectDN = $checkUserObject.DistinguishedName | select-object
	} catch {
		Write-Host "Not able to find $($MemberNameValue) in current AD - KO"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return 
	}
	
	If ($TTLValue) {
		try {
			Set-ADObject -Identity "$($CheckShadowObjectDN)" -Add @{'member'="<TTL=$($TTLValue),$($checkUserObjectDN)>"}
		} catch {
			Write-Host "Not able to add $($MemberNameValue) to $($GroupNameValue) with TTL $($TTLValue) - KO"  -foregroundcolor "Red"
			write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
			write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
			return 
		}
	} Else {
		try {
			Set-ADObject -Identity "$($CheckShadowObjectDN)" -Add @{'member'="$($checkUserObjectDN)"}
		} catch {
			Write-Host "Not able to add $($MemberNameValue) to $($GroupNameValue) - KO"  -foregroundcolor "Red"
			write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
			write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
			return 
		}
	}

	$CheckObject = get-adobject -Filter "ObjectClass -eq 'msDS-ShadowPrincipal' -and Name -eq '$($GroupNameValue)'" -SearchBase "$($ShadowGroupPath)" -properties *
	$CheckObject
}

function Remove-ADShadowGroupMember {
	Param(
	  [Parameter(Mandatory=$true,Position=1)]
		[string]$GroupNameValue,
	  [Parameter(Mandatory=$true,Position=2)]
		[string]$MemberNameValue,
     [parameter(Mandatory=$true,Position=3)]
     [ValidateSet("user", "group")]
        [String]$TypeValue
	)
	<#
	.SYNOPSIS 
	Remove an existing  member in an existing AD ShadowGroup

	.DESCRIPTION
	Remove an existing member in an existing AD ShadowGroup.

	.PARAMETER GroupNameValue
	Mandatory parameter
	-GroupNameValue string
	Provide Shadow Group name to be used in configuration partition of directory (cn=Shadow Principal Configuration,cn=Services...) (object to be searched only in the current AD)
	
	.PARAMETER MemberNameValue
	Mandatory parameter
	-MemberNameValue string
	Provide the name of user or group to be removed in the "member" attribute of the AD Shadow Group (object to be searched only in the current AD)
	
	.PARAMETER MemberNameValue
	Mandatory parameter
	-TypeValue string (user or group)
	Provide the type of member to remove (user or group) (object to be searched only in the current AD)
	
	.OUTPUTS
	TypeName: Microsoft.ActiveDirectory.Management.ADObject
	
	CanonicalName                   : admin.ad/Configuration/Services/Shadow Principal Configuration/PROD-Domain Admins
	CN                              : PROD-Domain Admins
	Created                         : 08/03/2017 16:00:41
	createTimeStamp                 : 08/03/2017 16:00:41
	Deleted                         :
	Description                     :
	DisplayName                     :
	DistinguishedName               : CN=PROD-Domain Admins,CN=Shadow Principal
									  Configuration,CN=Services,CN=Configuration,DC=admin,DC=ad
	dSCorePropagationData           : {01/01/1601 01:00:00}
	instanceType                    : 4
	isDeleted                       :
	LastKnownParent                 :
	member                          : {CN=Temp Prod Admins Shadow,OU=Admins,DC=admin,DC=ad, CN=Temp Prod
									  Admins,OU=Admins,DC=admin,DC=ad, CN=Prod Admins,OU=Admins,DC=admin,DC=ad}
	Modified                        : 08/03/2017 19:12:47
	modifyTimeStamp                 : 08/03/2017 19:12:47
	msDS-ShadowPrincipalSid         : S-1-1-11-1111111111-1111111111-111111111-111
	Name                            : PROD-Domain Admins
	nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
	ObjectCategory                  : CN=ms-DS-Shadow-Principal,CN=Schema,CN=Configuration,DC=admin,DC=ad
	ObjectClass                     : msDS-ShadowPrincipal
	ObjectGUID                      : 37e6ba38-1787-41ef-937f-02a7c0be6fc3
	ProtectedFromAccidentalDeletion : False
	sDRightsEffective               : 11
	uSNChanged                      : 16646
	uSNCreated                      : 16442
	whenChanged                     : 08/03/2017 19:12:47
	whenCreated                     : 08/03/2017 16:00:41

	.EXAMPLE
	C:\PS> Remove-ADShadowGroupMember -GroupNameValue "Shadow-Domain Admins" -MemberNameValue "Domain Admins" -MemberNameValue group
	
	.EXAMPLE
	C:\PS> Remove-ADShadowGroupMember -GroupNameValue "Shadow-Domain Admins" -MemberNameValue "Super-Admin" -MemberNameValue user
	#>
	try {
		import-module ActiveDirectory
	} catch {
		Write-Host "Not able to load active directory module - KO"  -foregroundcolor "Red"
		Write-Host "Please check RSAT is installed if you are running the script on A PC"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return 
	}
	$CurrentConfigurationPartDN = ([ADSI]"LDAP://RootDSE").configurationNamingContext
	$ADPArtDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
	$ShadowGroupPath = "cn=Shadow Principal Configuration,cn=Services,$($CurrentConfigurationPartDN)"
	$CheckShadowObject = get-adobject -Filter "ObjectClass -eq 'msDS-ShadowPrincipal' -and Name -eq '$($GroupNameValue)'" -SearchBase "$($ShadowGroupPath)" -properties member
	$CheckShadowObjectDN = $CheckShadowObject.DistinguishedName | select-object
	If (-not $CheckShadowObject) {
		Write-Host "ShadowPrincipal group $($GroupNameValue) not found ! - KO"  -foregroundcolor "Red"
		return
	}
	try {
		$checkUserObject = get-adobject -Filter "ObjectClass -eq '$($TypeValue)' -and cn -eq '$($MemberNameValue)'" -SearchBase "$($ADPArtDN)" -SearchScope Subtree -properties *
		$checkUserObjectDN = $checkUserObject.DistinguishedName | select-object
	} catch {
		Write-Host "Not able to find $($MemberNameValue) in current AD - KO"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return 
	}
	
	try {
		Set-ADObject -Identity "$($CheckShadowObjectDN)" -Remove @{'member'="$($checkUserObjectDN)"}
	} catch {
		Write-Host "Not able to remove $($MemberNameValue) from $($GroupNameValue) - KO"  -foregroundcolor "Red"
		write-host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor "Yellow"
		write-host "Error Message: $($_.Exception.Message)" -ForegroundColor "Yellow"
		return 
	}

	$CheckObject = get-adobject -Filter "ObjectClass -eq 'msDS-ShadowPrincipal' -and Name -eq '$($GroupNameValue)'" -SearchBase "$($ShadowGroupPath)" -properties *
	$CheckObject
}

Export-ModuleMember -Function Add-ADShadowGroupMember, Remove-ADShadowGroup, Add-ADShadowGroup, Get-ADShadowGroup, Remove-ADShadowGroupMember
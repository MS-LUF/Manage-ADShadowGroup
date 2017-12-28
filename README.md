# Manage-ADShadowGroup
A simple Powershell Module to help people managing Active Directory Shadow Group

# install Manage-ADShadowGroup from PowerShell Gallery repository
You can easily install it from powershell gallery repository https://www.powershellgallery.com/packages/Manage-ADShadowGroup/ using a simple powershell command and an internet access :-)
```
	Install-Module -Name Manage-ADShadowGroup
```
# import module from PowerShell 
```
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

```
# module content : Get-ADShadowGroup function
```
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
```

# module content : Add-ADShadowGroup funtion
```
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
```

# module content : Add-ADShadowGroupMember function
```
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
```

# module content : Remove-ADShadowGroupMember function
```
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
```
	
	

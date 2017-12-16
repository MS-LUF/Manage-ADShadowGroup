# Manage-ADShadowGroup
A simple Powershell Module to help people managing Active Directory Shadow Group

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

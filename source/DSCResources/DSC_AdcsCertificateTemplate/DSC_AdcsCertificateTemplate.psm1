$modulePath = Join-Path `
    -Path (
        Split-Path `
            -Path (
                Split-Path -Path $PSScriptRoot -Parent
            ) `
            -Parent
    ) `
    -ChildPath 'Modules'

# Import the ADCS Deployment Resource Common Module.
Import-Module `
    -Name (
        Join-Path `
            -Path $modulePath `
            -ChildPath (
                Join-Path `
                    -Path 'ActiveDirectoryCSDsc.Common' `
                    -ChildPath 'ActiveDirectoryCSDsc.Common.psm1'
            )
    )

Import-Module -Name (
    Join-Path -Path $modulePath -ChildPath 'DscResource.Common'
)

# Import Localization Strings.
$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

enum Flags
{
    CT_FLAG_AUTO_ENROLLMENT = 0x00000020
    CT_FLAG_MACHINE_TYPE = 0x00000040
    CT_FLAG_IS_CA = 0x00000080
    CT_FLAG_ADD_TEMPLATE_NAME = 0x00000200
    CT_FLAG_IS_CROSS_CA = 0x00000800
    CT_FLAG_IS_DEFAULT = 0x00010000
    CT_FLAG_IS_MODIFIED = 0x00020000
    CT_FLAG_DONOTPERSISTINDB = 0x00000400
    CT_FLAG_ADD_EMAIL = 0x00000002
    CT_FLAG_PUBLISH_TO_DS = 0x00000008
    CT_FLAG_EXPORTABLE_KEY = 0x00000010
}

enum DefaultKeySpec
{
    AT_KEYEXCHANGE = 1
    AT_SIGNATURE = 2
}

enum EnrollmentFlag
{
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
    CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
    CT_FLAG_PUBLISH_TO_KRA_CONTAINER = 0x00000004
    CT_FLAG_PUBLISH_TO_DS = 0x00000008
    CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
    CT_FLAG_AUTO_ENROLLMENT = 0x00000020
    CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
    CT_FLAG_USER_INTERACTION_REQUIRED = 0x00000100
    CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
    CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
    CT_FLAG_ADD_OCSP_NOCHECK = 0x00001000
    CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
    CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
    CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
    CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = `
        0x00010000
    CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
    CT_FLAG_SKIP_AUTO_RENEWAL = 0x00040000
}

enum PrivateKeyFlag
{
    CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
    CT_FLAG_EXPORTABLE_KEY = 0x00000010
    CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED = 0x00000020
    CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040
    CT_FLAG_REQUIRE_SAME_KEY_RENEWAL = 0x00000080
    CT_FLAG_USE_LEGACY_PROVIDER = 0x00000100
    CT_FLAG_ATTEST_NONE = 0x00000000
    CT_FLAG_ATTEST_REQUIRED = 0x00002000
    CT_FLAG_ATTEST_PREFERRED = 0x00001000
    CT_FLAG_ATTESTATION_WITHOUT_POLICY = 0x00004000
    CT_FLAG_EK_TRUST_ON_USE = 0x00000200
    CT_FLAG_EK_VALIDATE_CERT = 0x00000400
    CT_FLAG_EK_VALIDATE_KEY = 0x00000800
    CT_FLAG_HELLO_LOGON_KEY = 0x00200000
}

enum CertificateNameFlag
{
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
    CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
    CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x00800000
    CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
    CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000
    CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
    CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x08000000
    CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
    CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000
    CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
    CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000
    CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
}

enum KeyUsage
{
    digitalSignature = 0x8000
    nonRepudation = 0x4000
    keyEncipherment = 0x2000
    dataEncipherment = 0x1000
    keyAgreement = 0x0800
    keyCertSign = 0x0400
    cRLSign = 0x200
    encipherOnly = 0x0100
    decipherOnly = 0x0080
}
<#
.SYNOPSIS


.PARAMETER Name


.PARAMETER Ensure
Specifies whether the Template should be added or removed.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($script:localizedData.GettingAdcsTemplateStatusMessage -f $Name)
        ) -join '' )

    try
    {
        $ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
        $certificateTemplates = `
            [ADSI] `
            "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
        $certificateTemplate = `
            [ADSI] `
            "LDAP://CN=$Name,$($certificateTemplates.distinguishedName)"
    }
    catch
    {
        New-InvalidOperationException -Message (
            $script:localizedData.InvalidOperationGettingAdcsTemplateMessage `
            -f $Name
        ) -ErrorRecord $PSItem
    }

    if ($certificateTemplate | Get-Member -Name distinguishedName)
    {
        # Template is added

        # parse default CSPs

        $defaultCSPs = ($certificateTemplate.pKIDefaultCSPs -split ',').Trim()

        # remove numeric priority entries
        [int32]$result = 0
        $defaultCSPs = $defaultCSPs |
            Where-Object (-not ([int]::TryParse($PSItem, [ref]$result)))

        $result = @{
            Ensure = 'Present'
            Flags = Split-Flags `
                -Flags $certificateTemplate.flags `
                -Type ([Flags])
            DisplayName = $certificateTemplate.DisplayName
            DefaultKeySpec = `
                [DefaultKeySpec]$certificateTemplate.pKIDefaultKeySpec
            MaxIssuingDepth = $certificateTemplate.pKIMaxIssuingDepth
            CriticalExtensions = (
                $certificateTemplate.pKICriticalExtensions -split ','
            ).Trim()
            ExtendedKeyUsage = (
                $certificateTemplate.pKIExtendedKeyUsage -split ','
            ).Trim()
            DefaultCSPs = $defaultCSPs
            RASignature = $certificateTemplate.get('msPKI-RA-Signature')
            EnrollmentFlag = Split-Flags `
                -Flags $certificateTemplate.get('msPKI-Enrollment-Flag') `
                -Type ([EnrollmentFlag])
            PrivateKeyFlag = Split-Flags `
                -Flags $certificateTemplate.get('msPKI-Private-Key-Flag') `
                -Type ([PrivateKeyFlag])
            CertificateNameFlag = Split-Flags `
                -Flags $certificateTemplate.get('msPKI-Certificate-Name-Flag') `
                -Type ([CertificateNameFlag])
            MinimalKeySize = $certificateTemplate.get('msPKI-Minimal-Key-Size')
            TemplateSchemaVersion = $certificateTemplate.get(
                'msPKI-Template-Schema-Version'
            )
            CertTemplateOID = $certificateTemplate.get(
                'msPKI-Certificate-Application-Policy'
            )
            CertificateApplicationPolicy = ($certificateTemplate.get(
                'msPKI-Certificate-Application-Policy'
            ) -split ',').Trim()
            KeyUsage = Split-Flags `
                -Flags $certificateTemplate.pKIKeyUsage `
                -Type ([KeyUsage])
            ExpirationPeriod = New-TimeSpan `
                -Seconds $certificateTemplate.pKIExpirationPeriod / 1000000
            OverlapPeriod = New-TimeSpan `
                -Seconds $certificateTemplate.pKIOverlapPeriod / 1000000
        }
    }
    else
    {
        # Template is removed
        $result = @{
            Ensure = 'Absent'
        }
    }

    $result.Add('Name', $Name)
    return $result
} # function Get-TargetResource

<#
    .SYNOPSIS
        Adds or removes a CA Template.

    .PARAMETER Name
        Specifies the name of a certificate template. This name must always be the
        template short name without spaces, and not the template display name.

    .PARAMETER Ensure
        Specifies whether the Template should be added or removed.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,
        [Parameter()]
        [System.String]
        $DisplayName = $Name,
        [Parameter(Mandatory = $true)]
        [DefaultKeySpec]
        $DefaultKeySpec,
        [Parameter()]
        [Flags[]]
        $Flags,
        [Parameter()]
        [System.Int32]
        $MaxIssuingDepth = 0,
        [Parameter()]
        [Sytem.String[]]
        $CriticalExtensions,
        [Parameter()]
        [Sytem.String[]]
        [Parameter()]
        $ExtendedKeyUsage,
        [Parameter()]
        [ValidateSet(
            'Microsoft RSA SChannel Cryptographic Provider',
            'Microsoft DH SChannel Cryptographic Provider',
            'Microsoft Enhanced Cryptographic Provider v1.0',
            'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider',
            'Microsoft Enhanced RSA and AES Cryptographic Provider',
            'Microsoft Strong Cryptographic Provider'
        )]
        [System.String[]]
        $DefaultCSPs = @(
            'Microsoft RSA SChannel Cryptographic Provider',
            'Microsoft DH SChannel Cryptographic Provider'
        ),
        [Parameter()]
        [System.Int32]
        $RASignature = 0,
        [Parameter()]
        [EnrollmentFlag[]]
        $EnrollmentFlag,
        [Parameter()]
        [PrivateKeyFlag[]]
        $PrivateKeyFlag,
        [Parameter()]
        [CertificateNameFlag[]]
        $CertificateNameFlag,
        [Parameter()]
        [System.Int32]
        $MinimalKeySize = 2048,
        [Parameter()]
        [ValidateSet(1, 2, 3, 4)]
        $TemplateSchemaVersion = 2,
        [Parameter()]
        [System.String]
        $CertTemplateOID,
        [Parameter()]
        [System.String[]]
        $CertificateApplicationPolicy,
        [Parameter()]
        [KeyUsage[]]
        $KeyUsage,
        [Parameter()]
        [System.TimeSpan]
        $ExpirationPeriod = (New-TimeSpan -Days 365),
        [Parameter()]
        [System.TimeSpan]
        $OverlapPeriod = (New-TimeSpan -Days 30),
        [Parameter()]
        [System.String]
        [ValidateSet('Present', 'Absent')]
        $Ensure = 'Present'
    )

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($script:localizedData.SettingAdcsTemplateStatusMessage -f $Name)
        ) -join '' )

    try
    {
        $ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
        $certificateTemplates = `
            [ADSI] `
            "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
        $certificateTemplate = `
            [ADSI] `
            "LDAP://CN=$Name,$($certificateTemplates.distinguishedName)"
    }
    catch
    {
        New-InvalidOperationException -Message (
            $script:localizedData.InvalidOperationAddingAdcsTemplateMessage `
                -f $Name
        ) -ErrorRecord $PSItem
    }
    if ($Ensure -eq 'Present')
    {
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($script:localizedData.AddingAdcsTemplateMessage -f $Name)
            ) -join '' )

        try
        {
            <#
            Check, if certificate template alread exists, by checking the
            existence of distinguishedName property
            #>
            if (
                -not ($certificateTemplate | Get-Member -Name distinguishedName)
                ) {
                $certificateTemplate = $ADSI.Create(
                    "pKICertificateTemplate", "CN=$Name"
                )
                # $certificateTemplate.put(
                #     "distinguishedname",
                #     "CN=$Name,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
                # )
            }
            $certificateTemplate.flags = Join-Flags -Flags $Flags

            $certificateTemplate.displayName = $DisplayName

            $revision = $certificateTemplate.revision
            if (-not $revision) { $revision = 0}
            $revision++
            $certificateTemplate.revision = $revision
            $certificateTemplate.pKIDefaultKeySpec = $DefaultKeySpec
            $certificateTemplate.pKIMaxIssuingDepth = $MaxIssuingDepth
            $certificateTemplate.pKICriticalExtensions = `
                $CriticalExtensions -join ', '
            $certificateTemplate.pKIExtendedKeyUsage = `
                $ExtendedKeyUsage -join ', '

            for ($i = 0; $i -lt $DefaultCSPs.Count; $i++)
            {
                $DefaultCSPs[$i] = "$($i+1),$DefaultCSPs"
            }
            $certificateTemplate.pKIDefaultCSPs = `
                $DefaultCSPs -join ', '

            $certificateTemplate.SetInfo()

            $certificateTemplate.put('msPKI-RA-Signature', $RASignature)

            $certificateTemplate.put(
                'msPKI-Enrollment-Flag', (Join-Flags -Flags $EnrollmentFlag)
            )

            $certificateTemplate.put(
                'msPKI-Private-Key-Flag', (Join-Flags -Flags $PrivateKeyFlag)
            )

            $certificateTemplate.put(
                'msPKI-Certificate-Name-Flag',
                (Join-Flags -Flags $CertificateNameFlag)
            )

            $certificateTemplate.put(
                'msPKI-Minimal-Key-Size', $MinimalKeySize
            )
            $certificateTemplate.put(
                'msPKI-Template-Schema-Version', $TemplateSchemaVersion
            )
            $certificateTemplate.put('msPKI-Template-Minor-Revision', '0')
            $certificateTemplate.put(
                'msPKI-Cert-Template-OID', $CertTemplateOID
            )
            $certificateTemplate.put(
                'msPKI-Certificate-Application-Policy',
                $CertificateApplicationPolicy -join ', '
            )

            $certificateTemplate.SetInfo()

            $certificateTemplate.pKIKeyUsage = Join-Flags -Flags $KeyUsageValue
            $certificateTemplate.pKIExpirationPeriod = `
                $ExpirationPeriod.TotalMilliseconds * 1000
            $certificateTemplate.pKIOverlapPeriod = `
                $OverlapPeriod.TotalMilliseconds * 1000
            $NewTempl.SetInfo()
        }
        catch
        {
            New-InvalidOperationException -Message (
                $script:localizedData.InvalidOperationAddingAdcsTemplateMessage `
                -f $Name
            ) -ErrorRecord $PSItem
        }
    }
    else
    {
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($script:localizedData.RemovingAdcsTemplateMessage -f $Name)
            ) -join '' )

        try
        {
            <#
            Check, if certificate template alread exists, by checking the
            existence of distinguishedName property
            #>
            if ($certificateTemplate | Get-Member -Name distinguishedName)
            {
                $certificateTemplate.DeleteTree
            }
        }
        catch
        {
            New-InvalidOperationException -Message (
                $script:localizedData.InvalidOperationRemovingAdcsTemplateMessage `
                    -f $Name
            ) -ErrorRecord $PSItem
        }
    }
} # function Set-TargetResource

<#
    .SYNOPSIS
        Tests if the CA Template is in the desired state.

    .PARAMETER Name
        Specifies the name of a certificate template. This name must always be the
        template short name without spaces, and not the template display name.

    .PARAMETER Ensure
        Specifies whether the Template should be added or removed.

    .OUTPUTS
        Returns true if the CA Template is in the desired state.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,
        [Parameter()]
        [System.String]
        $DisplayName = $Name,
        [Parameter(Mandatory = $true)]
        [DefaultKeySpec]
        $DefaultKeySpec,
        [Parameter()]
        [Flags[]]
        $Flags,
        [Parameter()]
        [System.Int32]
        $MaxIssuingDepth = 0,
        [Parameter()]
        [Sytem.String[]]
        $CriticalExtensions,
        [Parameter()]
        [Sytem.String[]]
        $ExtendedKeyUsage,
        [Parameter()]
        [ValidateSet(
            'Microsoft RSA SChannel Cryptographic Provider',
            'Microsoft DH SChannel Cryptographic Provider',
            'Microsoft Enhanced Cryptographic Provider v1.0',
            'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider',
            'Microsoft Enhanced RSA and AES Cryptographic Provider',
            'Microsoft Strong Cryptographic Provider'
        )]
        [System.String[]]
        $DefaultCSPs = @(
            'Microsoft RSA SChannel Cryptographic Provider',
            'Microsoft DH SChannel Cryptographic Provider'
        ),
        [Parameter()]
        [System.Int32]
        $RASignature = 0,
        [Parameter()]
        [EnrollmentFlag[]]
        $EnrollmentFlag,
        [Parameter()]
        [PrivateKeyFlag[]]
        $PrivateKeyFlag,
        [Parameter()]
        [CertificateNameFlag[]]
        $CertificateNameFlag,
        [Parameter()]
        [System.Int32]
        $MinimalKeySize = 2048,
        [Parameter()]
        [ValidateSet(1, 2, 3, 4)]
        $TemplateSchemaVersion = 2,
        [Parameter()]
        [System.String]
        $CertTemplateOID,
        [Parameter()]
        [System.String[]]
        $CertificateApplicationPolicy,
        [Parameter()]
        [KeyUsage[]]
        $KeyUsage,
        [Parameter()]
        [System.TimeSpan]
        $ExpirationPeriod = (New-TimeSpan -Days 365),
        [Parameter()]
        [System.TimeSpan]
        $OverlapPeriod = (New-TimeSpan -Days 30),
        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($script:localizedData.TestingAdcsTemplateStatusMessage -f $Name)
        ) -join '' )

    $currentState = Get-TargetResource -Name $Name
    $result = $true
    if ($Ensure -eq 'Present')
    {
        if ($currentState.Ensure -eq 'Present')
        {
            # CA Template is added and should be - change not required
            Write-Verbose -Message (@(
                "$($MyInvocation.MyCommand): "
                $script:localizedData.AdcsCATemplateAddedAndShouldBeMessage `
                    -f $Name
            ) -join '' )

            # Compare parameters
            foreach ($item in $PSBoundParameters.Keys)
            {
                $result = $result `
                    -and ($PSBoundParameters[$item] -eq $currentState[$item])
            }

            if ($result)
            {
                Write-Verbose -Message (@(
                    "$($MyInvocation.MyCommand): "
                    $script:localizedData.AdcsTemplateSettingsEqualMessage `
                        -f $Name
                ) -join '' )
            } else
            {
                Write-Verbose -Message (@(
                    "$($MyInvocation.MyCommand): "
                    $script:localizedData.AdcsTemplateSettingsNotEqualMessage `
                        -f $Name
                ) -join '' )
            }
        }
        else
        {
            $result = $false
            # CA Template is not added but should be - change required
            Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $script:localizedData.AdcsTemplateNotAddedButShouldBeMessage `
                    -f $Name
            ) -join '' )
        }
    }
    else
    {
        if ($currentState.Ensure -eq 'Present')
        {
            # CA Template is installed and should not be - change required
            Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $script:localizedData.AdcsCATemplateAddedButShouldNotBeMessage `
                    -f $Name
            ) -join '' )

            $result = $false
        }
        else
        {
            # CA Template is not added and should not be - change not required
            Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $script:localizedData.AdcsTemplateNotAddedAndShouldNotBeMessage `
                    -f $Name
            ) -join '' )

            $result = $true
        }
    }
    return $result
} # function Test-TargetResource

function Split-Flags
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int32]
        $Flags,
        [Parameter(Mandatory = $true)]
        [Type]
        $Type
    )

    $result = @()
    foreach ($itemName in [Enum]::GetNames($Type))
    {
        $item = [Enum]::Parse($Type, $itemName)
        if ($Flags -band $item)
        {
            $result += $item
        }
    }
    return $result
}

function Join-Flags
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int[]]
        $Flags
    )

    $result = 0
    foreach ($flag in $Flags)
    {
        $result = $result -bor $flag
    }
    return $result
}


# Export-ModuleMember -Function *-TargetResource

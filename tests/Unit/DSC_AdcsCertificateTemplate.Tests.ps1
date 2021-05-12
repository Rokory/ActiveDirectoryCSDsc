$script:dscModuleName = 'ActiveDirectoryCSDsc'
$script:dscResourceName = 'DSC_ADCSCertificateTemplate'

function Invoke-TestSetup
{
    try
    {
        Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -Tasks build" first.'
    }

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'

    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\TestHelpers\CommonTestHelper.psm1')
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\TestHelpers\AdcsStub.psm1')
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
    Remove-Module -Name AdcsStub -Force
}

Invoke-TestSetup

try
{
    InModuleScope $script:dscResourceName {
        class DirectoryEntry
        {
            [string]$cn
            [string]$displayName
            [string]$distinguishedName
            [int]$flags
            [string]${msPKI-Cert-Template-OID}
            [int]${msPKI-Certificate-Name-Flag}
            [int]${msPKI-Enrollment-Flag}
            [int]${msPKI-Minimal-Key-Size}
            [int]${msPKI-Private-Key-Flag}
            [int]${msPKI-RA-Signature}
            [int]${msPKI-Template-Schema-Version}
            [string]$name
            [string]$pKICriticalExtensions
            [string[]]$pKIDefaultCSPs
            [int]$pKIDefaultKeySpec
            [byte[]]$pKIExpirationPeriod
            [string[]]$pKIExtendedKeyUsage
            [byte[]]$pKIKeyUsage
            [int]$pKIMaxIssuingDepth
            [byte[]]$pKIOverlapPeriod
            [int]$revision

            [object]get($attribute)
            {
                return $this.$attribute
            }

            put($attribute, $value)
            {
                $this.$attribute = $value
            }

            DirectoryEntry() {}
            DirectoryEntry(
                [string]$name
                , [string]$displayName
                , [int]$flags
                , [string]${msPKI-Cert-Template-OID}
                , [int]${msPKI-Certificate-Name-Flag}
                , [int]${msPKI-Enrollment-Flag}
                , [int]${msPKI-Minimal-Key-Size}
                , [int]${msPKI-Private-Key-Flag}
                , [int]${msPKI-RA-Signature}
                , [int]${msPKI-Template-Schema-Version}
                , [string]$pKICriticalExtensions
                , [string[]]$pKIDefaultCSPs
                , [int]$pKIDefaultKeySpec
                , [byte[]]$pKIExpirationPeriod
                , [string[]]$pKIExtendedKeyUsage
                , [byte[]]$pKIKeyUsage
                , [int]$pKIMaxIssuingDepth
                , [byte[]]$pKIOverlapPeriod
                , [int]$revision
            )
            {
                $this.name = $name
                $this.displayName = $displayName
                $this.flags = $flags
                $this.{msPKI-Cert-Template-OID} = ${msPKI-Cert-Template-OID}
                $this.{msPKI-Certificate-Name-Flag} = ${msPKI-Certificate-Name-Flag}
                $this.{msPKI-Enrollment-Flag} = ${msPKI-Enrollment-Flag}
                $this.{msPKI-Minimal-Key-Size} = ${msPKI-Minimal-Key-Size}
                $this.{msPKI-Private-Key-Flag} = ${msPKI-Private-Key-Flag}
                $this.{msPKI-RA-Signature} = ${msPKI-RA-Signature}
                $this.{msPKI-Template-Schema-Version} = ${msPKI-Template-Schema-Version}
                $this.pKICriticalExtensions = $pKICriticalExtensions
                $this.pKIDefaultCSPs = $pKIDefaultCSPs
                $this.pKIDefaultKeySpec = $pKIDefaultKeySpec
                $this.pKIExpirationPeriod = $pKIExpirationPeriod
                $this.pKIExtendedKeyUsage = $pKIExtendedKeyUsage
                $this.pKIKeyUsage = $pKIKeyUsage
                $this.pKIMaxIssuingDepth = $pKIMaxIssuingDepth
                $this.pKIOverlapPeriod = $pKIOverlapPeriod
                $this.revision = $revision
            }
        }

        $mockTemplateList = @(
            [DirectoryEntry]::new(
                'User'
                , 'User'
                , '66106'
                , '1.3.6.1.4.1.311.21.8.2133000.13205347.10833547.10270400.7309790.175.1.1'
                , -150994944
                , 41
                , 2048
                , 16
                , 0
                , 1
                , 2.5.29.15
                , @(
                    '2,Microsoft Base Cryptographic Provider v1.0'
                    '1,Microsoft Enhanced Cryptographic Provider v1.0'
                )
                , 1
                , @(0, 64, 57, 135, 46, 225, 254, 255)
                , @(
                    '1.3.6.1.4.1.311.10.3.4'
                    '1.3.6.1.5.5.7.3.4'
                    '1.3.6.1.5.5.7.3.2'
                )
                , @(160, 0)
                , 0
                , @(0, 128, 166, 10, 255, 222, 255, 255)
                , 3
            )
        )

        $testTemplatePresent = @{
            Name = 'User'
        }


        Describe 'AdcsCertificateTemplate\Get-TargetResource' {
            Context 'When the template is installed' {
                function Get-CertificateTemplate
                {
                    [OutputType([DirectoryEntry])]
                    [CmdletBinding()]
                    param (
                        [Parameter()]
                        [string]
                        $Name
                    )
                    return $mockTemplateList
                }
                # Mock `
                #     -CommandName Get-CertificateTemplate `
                #     -MockWith { $mockTemplateList }

                $result = Get-TargetResource @testTemplatePresent

                It 'Should return Ensure set to Present' {
                    $result.Ensure | Should -Be 'Present'
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}

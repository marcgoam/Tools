function Convert-MarcLDAPProperty {
    # [Código sin cambios - independiente]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )
    # ... [mantén todo el código original de Convert-MarcLDAPProperty]
}

function Get-DomainMarc {
    # Sin cambios - usa DirectoryServices directamente
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]$Domain,
        [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty
    )
    # ... [mantén código original]
}

function Get-DomainSPNTicketMarc {
    # Sin cambios - independiente de Get-DomainSearcher
    # ... [mantén código original]
}

function Get-DomainUserMarc {
    [OutputType('PowerView.User')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]$Identity,
        
        [Switch]$SPN, [Switch]$AdminCount, [Switch]$AllowDelegation, [Switch]$DisallowDelegation,
        [Switch]$TrustedToAuth, [Switch]$PreauthNotRequired,
        [String]$Domain, [String]$LDAPFilter, [String[]]$Properties,
        [String]$SearchBase, [String]$Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')][String]$SearchScope = 'Subtree',
        [Int]$ResultPageSize = 200, [Int]$ServerTimeLimit,
        [String]$SecurityMasks, [Switch]$Tombstone,
        [Switch]$FindOne, [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]$Raw
    )

    BEGIN {
        # REEMPLAZO DIRECTO: Creamos el searcher sin Get-DomainSearcher
        $SearcherArguments = @{}
        if ($Domain) { $SearcherArguments['Domain'] = $Domain }
        if ($Server) { $SearcherArguments['Server'] = $Server }
        if ($Credential) { $SearcherArguments['Credential'] = $Credential }
        
        $UserSearcher = New-DomainSearcher @SearcherArguments -SearchScope $SearchScope -ResultPageSize $ResultPageSize
    }

    PROCESS {
        # [resto del código sin cambios hasta la línea del searcher]
        if ($UserSearcher) {
            # ... [toda la lógica de filtro igual]
            
            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "[Get-DomainUserMarc] filter string: $($UserSearcher.filter)"

            if ($FindOne) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            
            # ... [resto sin cambios]
        }
    }
}

# NUEVA FUNCIÓN AUXILIAR: Reemplaza Get-MarcDomainSearcher
function New-DomainSearcher {
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [String]$Domain, [String]$LDAPFilter, [String[]]$Properties,
        [String]$SearchBase, [String]$SearchBasePrefix, [String]$Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')][String]$SearchScope = 'Subtree',
        [Int]$ResultPageSize = 200, [Int]$ServerTimeLimit = 120,
        [String]$SecurityMasks, [Switch]$Tombstone,
        [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty
    )

    # LÓGICA SIMPLIFICADA del Get-MarcDomainSearcher original
    if (-not $Server) {
        try { $Server = (Get-DomainMarc).PdcRoleOwner.Name }
        catch { $Server = $env:LOGONSERVER.TrimStart('\\') }
    }

    $SearchString = "LDAP://$Server"
    if ($SearchBase) { $SearchString += "/$SearchBase" }
    else { 
        if ($Domain) { $SearchString += "/DC=$($Domain.Replace('.', ',DC='))" }
        else { $SearchString += "/" }
    }

    Write-Verbose "[New-DomainSearcher] Search string: $SearchString"

    if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
        $DomainEntry = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainEntry)
    } else {
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    }

    $Searcher.PageSize = $ResultPageSize
    $Searcher.SearchScope = $SearchScope
    $Searcher.CacheResults = $False
    $Searcher.ReferralChasing = 'All'

    if ($ServerTimeLimit) { $Searcher.ServerTimeLimit = $ServerTimeLimit }
    if ($Tombstone) { $Searcher.Tombstone = $True }
    if ($LDAPFilter) { $Searcher.Filter = $LDAPFilter }
    
    if ($Properties) { $Searcher.PropertiesToLoad.AddRange($Properties) }

    $Searcher
}

function Invoke-KerberoMarc {
    # Actualizado para usar Get-DomainUserMarc que ya no necesita Get-DomainSearcher
    [CmdletBinding()]
    Param(
        [String[]]$Identity, [String]$Domain, [String]$LDAPFilter,
        [String]$SearchBase, [String]$Server,
        [String]$SearchScope = 'Subtree', [Int]$ResultPageSize = 200,
        [Int]$ServerTimeLimit, [Switch]$Tombstone,
        [Int]$Delay = 0, [Double]$Jitter = .3,
        [String]$OutputFormat = 'John',
        [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty
    )

    $UserSearcherArguments = @{
        'SPN' = $True
        'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
    }
    if ($Domain) { $UserSearcherArguments['Domain'] = $Domain }
    if ($LDAPFilter) { $UserSearcherArguments['LDAPFilter'] = $LDAPFilter }
    if ($SearchBase) { $UserSearcherArguments['SearchBase'] = $SearchBase }
    if ($Server) { $UserSearcherArguments['Server'] = $Server }
    if ($SearchScope) { $UserSearcherArguments['SearchScope'] = $SearchScope }
    if ($ResultPageSize) { $UserSearcherArguments['ResultPageSize'] = $ResultPageSize }
    if ($ServerTimeLimit) { $UserSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
    if ($Tombstone) { $UserSearcherArguments['Tombstone'] = $Tombstone }
    if ($Credential) { $UserSearcherArguments['Credential'] = $Credential }

    Get-DomainUserMarc @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | 
    Get-DomainSPNTicketMarc -Delay $Delay -OutputFormat $OutputFormat -Jitter $Jitter
}

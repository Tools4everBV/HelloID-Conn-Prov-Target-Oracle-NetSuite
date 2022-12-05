#####################################################
# HelloID-Conn-Prov-Target-Oracle-Netsuite-Update
#
# Version: 1.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Account mapping
$account = [PSCustomObject]@{
    entityId     = $p.ExternalId
    autoname     = $false
    firstName    = $p.Name.GivenName
    Lastname     = $p.Name.FamilyName
    gender       = [PSCustomObject]@{  # Enum:  b , ns , nb , m , f
        id = 'b'
    }
    salutation   = $p.Details.Gender
    email        = $p.Contact.Business.Email
    customForm   = [PSCustomObject]@{  # No Webcall availible to get the ID
        id = '93' #"Company Medewerkerformulier - Restricted"
    }
    subsidiary   = [PSCustomObject]@{
        id = '2'  # ToDo (Lookup Departments based on Name? )
    }
    issalesrep   = $false
    issupportrep = $false
    hireDate     = $([datetime]$p.PrimaryContract.StartDate).ToString('yyyy-MM-dd')
    title        = $p.PrimaryContract.Title.Name
    # Lookup is performed to gather the Id of the department
    department   = [PSCustomObject]@{
        name = 'Algemeen'     # $p.PrimaryContract.Department.DisplayName
        id   = ''
    }
}

if (-not [string]::isnullorempty($mRef)) {
    $account | Add-Member -NotePropertyMembers @{
        supervisor = [PSCustomObject]@{
            id = $mRef  # The ID of the SuperVisor
        }
    }
}

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

#region functions
function ConvertTo-EncodedString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.String]
        $String
    )

    $doNotEncodeCharacters = [char[]]'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~'
    $result = [System.Text.StringBuilder]::new()

    foreach ($character in $String.ToCharArray()) {
        if ($doNotEncodeCharacters -contains $character) {
            $null = $result.Append($character)
        } else {
            $null = $result.Append(('%{0:X2}' -f [int] $character))
        }
    }

    $result.ToString()
}

function Initialize-Oauth1Header {
    [CmdletBinding()]
    param(
        [string]
        $Uri,

        [string]
        $method
    )
    try {
        # Make sure the encoding is correct, Because when it isn't you are unauthorized
        $Uri = ([System.Uri]::new($Uri).AbsoluteUri)

        $oauthVersion = '1.0'
        $oauthSignatureMethod = 'HMAC-SHA256'
        $oauthNonce = -join ((65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object { [char]$_ })
        $oauthTimestamp = [int64](([datetime]::UtcNow) - (Get-Date '1/1/1970')).TotalSeconds

        $ouathParameters = [System.Collections.Generic.list[String]]@()
        $ouathParameters.Add("oauth_consumer_key=$($config.ConsumerKey)")
        $ouathParameters.Add("oauth_nonce=$($oauthNonce)")
        $ouathParameters.Add("oauth_signature_method=$($oauthSignatureMethod)")
        $ouathParameters.Add("oauth_timestamp=$($oauthTimestamp)")
        $ouathParameters.Add("oauth_token=$($config.AccessToken)")
        $ouathParameters.Add("oauth_version=$($oauthVersion)")


        # Check if Url contains additional Query Paramaters and add them to the list $ouathParameters
        if ($Uri -like '*`?*') {
            $absoluteUri = $Uri.Substring(0, $Uri.IndexOf('?')).ToLower()
            $queryParams = $Uri.Substring($Uri.IndexOf('?')).Trim('?')

            $queryParamSplitted = $queryParams.Split('&')
            $ouathParameters.AddRange($queryParamSplitted)
        } else {
            $absoluteUri = $uri.ToLower()
        }
        # Make sure the paramaters are sorted a-z, otherwise you are unauthorized.
        $baseString = ($ouathParameters | Sort-Object) -join '&'

        $signatureBaseString = $Method + '&' + (ConvertTo-EncodedString -String $absoluteUri) + '&' + (ConvertTo-EncodedString -String $baseString)

        $key = $config.ConsumerSecret + '&' + $config.TokenSecret
        $hmacsha1 = [System.Security.Cryptography.HMACSHA256]::new()
        $hmacsha1.Key = [System.Text.Encoding]::ASCII.GetBytes($key)
        $oauthSignature = [System.Convert]::ToBase64String($hmacsha1.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($signatureBaseString)))
        $oauthSignature = ConvertTo-EncodedString -String $oauthSignature

        $auth = 'OAuth '
        $auth += 'realm="' + $config.Realm + '",'
        $auth += 'oauth_consumer_key="' + $config.ConsumerKey + '",'
        $auth += 'oauth_nonce="' + $oauthNonce + '",'
        $auth += 'oauth_signature="' + $oauthSignature + '",'
        $auth += 'oauth_signature_method="' + $oauthSignatureMethod + '",'
        $auth += 'oauth_timestamp="' + $oauthTimestamp + '",'
        $auth += 'oauth_token="' + $config.AccessToken + '",'
        $auth += 'oauth_version="' + $oauthVersion + '"'

        Write-Output $auth

    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Resolve-Oracle-NetsuiteError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = ''
            FriendlyMessage  = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorDetails = $ErrorObject.Exception.Message + $ErrorObject.ErrorDetails.Message
            $httpErrorObj.FriendlyMessage = ($ErrorObject.ErrorDetails.Message | ConvertFrom-Json).'o:errorDetails'.detail
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -eq $ErrorObject.Exception.Response) {
                $httpErrorObj.ErrorDetails = $ErrorObject.Exception.Message
                $httpErrorObj.FriendlyMessage = $ErrorObject.Exception.Message
            }

            if ($null -ne $ErrorObject.ErrorDetails.Message) {
                $httpErrorObj.FriendlyMessage = ($ErrorObject.ErrorDetails.Message | ConvertFrom-Json).'o:errorDetails'.detail
                $httpErrorObj.ErrorDetails = $ErrorObject.Exception.Message + ($ErrorObject.ErrorDetails.Message | ConvertFrom-Json).'o:errorDetails'.detail
            }
        }
        Write-Output $httpErrorObj
    }
}
#endregion

# Begin
try {
    Write-Verbose "Verifying if a Oracle-Netsuite Employee account for [$($p.DisplayName)] exists"
    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add('Content-Type', 'application/json;charset=utf-8')
    $headers.Add('Accept', 'application/json;charset=utf-8')
    $headers.Add('Accept-Language', 'en')
    $headers.Add('Content-Language', 'en')

    # Get department id
    if (-not [string]::IsNullOrEmpty($account.department.name)) {
        Write-Verbose "Lookup Id of Department [$($account.department.name)]"
        $requestUri = "$($config.BaseUrl)/services/rest/record/v1/department?q=name is `"$($account.department.name)`""
        $Method = 'GET'
        $oauth1String = Initialize-Oauth1Header -Uri $requestUri -Method $Method
        $headers['Authorization'] = $oauth1String

        $splatParams = @{
            Uri     = $requestUri
            Method  = $Method
            Headers = $headers
        }
        $departmentId = (Invoke-RestMethod -Verbose:$false @splatParams).items.id | Select-Object -First 1

        $account.department.PsObject.Properties.Remove('name')
        $account.department.id = $departmentId
    }

    # Get Current Employee Account
    $requestUri = "$($config.BaseUrl)/services/rest/record/v1/employee/$aRef"
    $Method = 'GET'
    $oauth1String = Initialize-Oauth1Header -Uri $requestUri -Method $Method
    $headers['Authorization'] = $oauth1String

    $splatParams = @{
        Uri     = $requestUri
        Method  = $Method
        Headers = $headers
    }
    $currentAccountRaw = Invoke-RestMethod -Verbose:$false @splatParams

    $currentAccount = [PSCustomObject]@{
        entityId     = $currentAccountRaw.entityId
        autoname     = $false
        firstName    = $currentAccountRaw.firstName
        Lastname     = $currentAccountRaw.lastName
        gender       = [PSCustomObject]@{  # Enum:  b , ns , nb , m , f
            id = $currentAccountRaw.gender.id
        }
        salutation   = $currentAccountRaw.salutation
        email        = $currentAccountRaw.email
        customForm   = [PSCustomObject]@{
            id = $currentAccountRaw.customForm.id
        }
        subsidiary   = [PSCustomObject]@{
            id = $currentAccountRaw.subsidiary.id
        }
        supervisor   = [PSCustomObject]@{
            id = $currentAccountRaw.supervisor.id
        }
        issalesrep   = $currentAccountRaw.issalesrep
        issupportrep = $currentAccountRaw.issupportrep
        hireDate     = $currentAccountRaw.hireDate
        title        = $currentAccountRaw.title
        department   = [PSCustomObject]@{
            id = $currentAccountRaw.department.id
        }
    }

    $splatCompareProperties = @{
        ReferenceObject  = @($currentAccount.PSObject.Properties)
        DifferenceObject = @($account.PSObject.Properties)
    }
    $propertiesChanged = (Compare-Object @splatCompareProperties -PassThru).Where({ $_.SideIndicator -eq '=>' })
    if ( $propertiesChanged -and ($null -ne $currentAccount)) {
        $action = 'Update'
        $dryRunMessage = "Account property(s) required to update: [$($propertiesChanged.name -join ",")]"
    } elseif (-not($propertiesChanged)) {
        $action = 'NoChanges'
        $dryRunMessage = 'No changes will be made to the account during enforcement'
    } elseif ($null -eq $currentAccount) {
        $action = 'NotFound'
        $dryRunMessage = "Oracle-Netsuite Employee account for: [$($p.DisplayName)] not found. Possibily deleted"
    }
    Write-Verbose $dryRunMessage

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        Write-Warning "[DryRun] $dryRunMessage"
    }

    # Process
    if (-not($dryRun -eq $true)) {
        switch ($action) {
            'Update' {
                Write-Verbose "Updating Oracle-Netsuite Employee account with accountReference: [$aRef]"
                $requestUri = "$($config.BaseUrl)/services/rest/record/v1/employee/$aRef"
                $Method = 'PATCH'
                $headers['Authorization'] = Initialize-Oauth1Header -Uri $requestUri -Method $Method
                $splatParams = @{
                    Uri         = $requestUri
                    Method      = $Method
                    Headers     = $headers
                    ContentType = 'application/json;charset=utf-8'
                    Body        = ($account | ConvertTo-Json)
                }
                $null = Invoke-RestMethod -Verbose:$false @splatParams #204

                $success = $true
                $auditLogs.Add([PSCustomObject]@{
                        Message = "Update Employee account was successful, Property(s) updated :$($propertiesChanged.name -join ',')"
                        IsError = $false
                    })
                break
            }

            'NoChanges' {
                Write-Verbose "No changes to Oracle-Netsuite account with accountReference: [$aRef]"
                $success = $true
                $auditLogs.Add([PSCustomObject]@{
                        Message = 'Oracle-Netsuite Employee account not requires changes during enforcement'
                        IsError = $false
                    })
                break
            }

            'NotFound' {
                $success = $false
                $auditLogs.Add([PSCustomObject]@{
                        Message = "Oracle-Netsuite Employee account for: [$($p.DisplayName)] not found. Possibily deleted"
                        IsError = $true
                    })
                break
            }
        }
    }
} catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Oracle-NetsuiteError -ErrorObject $ex
        $auditMessage = "Could not update Oracle-Netsuite Employee account. Error: $($errorObj.FriendlyMessage)"
        Write-Verbose "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update Oracle-Netsuite Employee account. Error: $($ex.Exception.Message)"
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $auditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
    # End
} finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Account   = $account
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}

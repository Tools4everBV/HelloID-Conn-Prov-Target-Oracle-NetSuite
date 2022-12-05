#####################################################
# HelloID-Conn-Prov-Target-Oracle-Netsuite-Create
#
# Version: 1.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
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
    isInactive   = $true
    salutation   = $p.Details.Gender
    email        = $p.Contact.Business.Email
    customForm   = [PSCustomObject]@{ # No Webcall availible to get the ID
        id = '93' #"Company Medewerkerformulier - Restricted"
    }
    # https://$($config.BaseUrl).suitetalk.api.netsuite.com/services/rest/record/v1/subsidiary?q=name is "Company B.V."
    subsidiary   = [PSCustomObject]@{
        id = '2'
    }
    issalesrep   = $false
    issupportrep = $false
    hireDate     = $p.PrimaryContract.StartDate
    title        = $p.PrimaryContract.Title.Name
    # Lookup is performed in the code below to gather the Id of the department
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

# Set to true if accounts in the target system must be updated
$updatePerson = $false

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

        # Check if Url contains additional Query Parameters and add them to the list $ouathParameters
        if ($Uri -like '*`?*') {
            $absoluteUri = $Uri.Substring(0, $Uri.IndexOf('?')).ToLower()
            $queryParams = $Uri.Substring($Uri.IndexOf('?')).Trim('?')

            $queryParamSplitted = $queryParams.Split('&')
            $ouathParameters.AddRange($queryParamSplitted)
        } else {
            $absoluteUri = $uri.ToLower()
        }
        # Make sure the Parameters are sorted a-z, otherwise you are unauthorized.
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
    # Verify if a user must be either [created and correlated], [updated and correlated] or just [correlated]
    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add('Content-Type', 'application/json')
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

    # Verify if Employee Account Exists
    $requestUri = "$($config.BaseUrl)/services/rest/record/v1/employee?q=entityid is `"$($account.entityId)`""
    $Method = 'GET'
    $oauth1String = Initialize-Oauth1Header -Uri $requestUri -Method $Method
    $headers['Authorization'] = $oauth1String

    $splatParams = @{
        Uri     = $requestUri
        Method  = $Method
        Headers = $headers
    }
    $response = Invoke-RestMethod -Verbose:$false @splatParams

    $responseUser = $response.items | Select-Object -First 1

    if ($null -eq $responseUser) {
        $action = 'Create-Correlate'
    } elseif ($updatePerson -eq $true) {
        $action = 'Update-Correlate'
    } else {
        $action = 'Correlate'
    }

    # Add a warning message showing what will happen during enforcement
    if ($dryRun -eq $true) {
        Write-Warning "[DryRun] $action Oracle-Netsuite account for: [$($p.DisplayName)], will be executed during enforcement"
    }

    # Process
    if (-not($dryRun -eq $true)) {
        switch ($action) {
            'Create-Correlate' {
                Write-Verbose 'Creating and correlating Oracle-Netsuite Employee account'
                $requestUri = "$($config.BaseUrl)/services/rest/record/v1/employee"
                $Method = 'POST'
                $headers['Authorization'] = Initialize-Oauth1Header -Uri $requestUri -Method $Method
                $splatParams = @{
                    Uri         = $requestUri
                    Method      = $Method
                    Headers     = $headers
                    ContentType = 'application/json;charset=utf-8'
                    Body        = ($account | ConvertTo-Json)
                }
                $response = Invoke-RestMethod -Verbose:$false @splatParams

                # Get Account after creation for account reference
                $requestUri = "$($config.BaseUrl)/services/rest/record/v1/employee?q=entityid is `"$($account.entityId)`""
                $Method = 'GET'
                $headers['Authorization'] = Initialize-Oauth1Header -Uri $requestUri -Method $Method
                $splatParams = @{
                    Uri     = $requestUri
                    Method  = $Method
                    Headers = $headers
                }
                $response = Invoke-RestMethod -Verbose:$false @splatParams

                if ($response.items.count -gt 1) {
                    throw "After create. Multiple Employee accounts found with [$($account.email)]. Ids found [$($response.items.id -join ', ')]"
                }

                $accountReference = $response.items.id | Select-Object -First 1
            }

            'Update-Correlate' {
                Write-Verbose 'Updating and correlating Oracle-Netsuite Employee account'
                $requestUri = "$($config.BaseUrl)/services/rest/record/v1/employee/$($responseUser.Id)"

                $Method = 'PATCH'
                $headers['Authorization'] = Initialize-Oauth1Header -Uri $requestUri -Method $Method

                $splatParams = @{
                    Uri         = $requestUri
                    Method      = $Method
                    Headers     = $headers
                    ContentType = 'application/json;charset=utf-8'
                    Body        = ($account | ConvertTo-Json)
                }
                $response = Invoke-RestMethod -Verbose:$false @splatParams

                $accountReference = $responseUser.Id
                break
            }

            'Correlate' {
                Write-Verbose 'Correlating Oracle-Netsuite Employee account'
                $accountReference = $responseUser.Id
                break
            }
        }

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Message = "$action Oracle-Netsuite Employee account was successful. AccountReference is: [$accountReference]"
                IsError = $false
            })
    }
} catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Oracle-NetsuiteError -ErrorObject $ex
        $auditMessage = "Could not $action Oracle-Netsuite Employee account. Error: $($errorObj.FriendlyMessage)"
        Write-Verbose "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not $action Oracle-Netsuite Employee account. Error: $($ex.Exception.Message)"
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $auditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
    # End
} finally {
    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $accountReference
        Auditlogs        = $auditLogs
        Account          = $account
        ExportData       = [PSCustomObject]@{
            AccountReference = $accountReference
        }
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}

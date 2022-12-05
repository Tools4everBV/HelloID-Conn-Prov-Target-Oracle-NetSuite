#####################################################
# HelloID-Conn-Prov-Target-Oracle-Netsuite-User-Create
#
# Version: 1.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# $aRef = $accountReference
$aRef = "$($p.Accounts.NetsuiteEmployee.AccountReference)"

$account = @{
    giveAccess       = $true
    requirePwdChange = $true
    sendEmail        = $true
    roles            = @{
        items = @(
            @{
                selectedRole = @{
                    id = 1  # Id of the Role
                }
            }
        )
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
            $queryParams = $Uri.Substring($Uri.IndexOf('?')).Trim('?').ToLower()

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
    if ([string]::IsNullOrEmpty($aRef)) {
        throw 'No Accountreference found. The connector is not properly configured, it relies on the NetSuite Employee Connector.'
    }

    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add('Content-Type', 'application/json')
    $headers.Add('Accept-Language', 'en')
    $headers.Add('Content-Language', 'en')

    try {
        $requestUri = "$($config.BaseUrl)/services/rest/record/v1/employee/$aRef"
        $Method = 'GET'
        $oauth1String = Initialize-Oauth1Header -Uri $requestUri -Method $Method
        $headers['Authorization'] = $oauth1String

        $splatParams = @{
            Uri     = $requestUri
            Method  = $Method
            Headers = $headers
        }
        $currentAccount = Invoke-RestMethod -Verbose:$false @splatParams
        $action = 'Found'
    } catch {
        if ($_.ErrorDetails.Message -like '*The record instance does not exist*') {
            $action = 'NotFound'
        } else {
            throw $_
        }
    }

    # Add a warning message showing what will happen during enforcement
    if ($dryRun -eq $true) {
        Write-Warning "[DryRun] Create Oracle-Netsuite User for: [$($p.DisplayName)], will be executed during enforcement"
    }

    # Process
    if (-not($dryRun -eq $true)) {
        switch ($action) {
            'Found' {
                if ($currentAccount.giveAccess -eq $true) {
                    $auditLogs.Add([PSCustomObject]@{
                            Message = 'Oracle-Netsuite User account was already created'
                            IsError = $false
                        })
                } else {
                    $requestUri = "$($config.BaseUrl)/services/rest/record/v1/employee/$aRef"
                    $Method = 'PATCH'
                    $headers['Authorization'] = Initialize-Oauth1Header -Uri $requestUri -Method $Method
                    $splatParams = @{
                        Uri         = $requestUri
                        Method      = $Method
                        Headers     = $headers
                        ContentType = 'application/json;charset=utf-8'
                        Body        = ($account | ConvertTo-Json -Depth 10)
                    }
                    $null = Invoke-RestMethod -Verbose:$false @splatParams #204
                    $auditLogs.Add([PSCustomObject]@{
                            Message = 'Create Oracle-Netsuite User account was successful'
                            IsError = $false
                        })
                }
                $success = $true
            }
            'NotFound' {
                $auditLogs.Add([PSCustomObject]@{
                        Message = "Oracle-Netsuite Employee Account not found for: [$($p.DisplayName)], could not Create User Account"
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
        $auditMessage = "Could not create Oracle-Netsuite User account. Error: $($errorObj.FriendlyMessage)"
        Write-Verbose "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not create Oracle-Netsuite User account. Error: $($ex.Exception.Message)"
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
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}

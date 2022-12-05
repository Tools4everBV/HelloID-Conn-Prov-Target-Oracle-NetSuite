$configuration = Get-Content C:\_Data\Git\Consultancy\github_helloid\HelloID-Conn-Prov-Target-Oracle-NetSuite\test\config.json | ConvertFrom-Json

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
            $null = $result.Append(('%{0:X2}' -f [System.Int32] $character))
        }
    }

    $result.ToString()
}
#endregion
$url                    = $configuration.BaseUrl
$method                 = 'GET'

$oauth_consumer_key     = $configuration.ConsumerKey
$oauth_consumer_secret  = $configuration.ConsumerSecret
$oauth_nonce            = -join ((65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object {[char]$_})
$oauth_signature_method = 'HMAC-SHA256'
$oauth_timestamp        = [int64](([datetime]::UtcNow)-(Get-Date '1/1/1970')).TotalSeconds
$oauth_token            = $configuration.AccessToken
$oauth_token_secret     = $configuration.TokenSecret
$oauth_version          = '1.0'
$oauth_realm            = $configuration.Realm

$base_string  = 'oauth_consumer_key=' + $oauth_consumer_key
$base_string += '&oauth_nonce=' + $oauth_nonce
$base_string += '&oauth_signature_method=' + $oauth_signature_method
$base_string += '&oauth_timestamp=' + $oauth_timestamp
$base_string += '&oauth_token=' + $oauth_token
$base_string += '&oauth_version=' + $oauth_version

$signature_base_string = $method + '&' + (ConvertTo-EncodedString -String $url) + '&' + (ConvertTo-EncodedString -String $base_string)

$key = $oauth_consumer_secret + '&' + $oauth_token_secret
$hmacsha1 = [System.Security.Cryptography.HMACSHA256]::new()
$hmacsha1.Key = [System.Text.Encoding]::ASCII.GetBytes($key)
$oauth_signature = [System.Convert]::ToBase64String($hmacsha1.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($signature_base_string)))
$oauth_signature = ConvertTo-EncodedString -String $oauth_signature

$auth  = 'OAuth '
$auth += 'realm="' + $oauth_realm + '",'
$auth += 'oauth_consumer_key="' + $oauth_consumer_key + '",'
$auth += 'oauth_nonce="' + $oauth_nonce + '",'
$auth += 'oauth_signature="' + $oauth_signature + '",'
$auth += 'oauth_signature_method="' + $oauth_signature_method + '",'
$auth += 'oauth_timestamp="' + $oauth_timestamp + '",'
$auth += 'oauth_token="' + $oauth_token + '",'
$auth += 'oauth_version="' + $oauth_version + '"'

$headers = [System.Collections.Generic.Dictionary[[String],[String]]]::new()
$headers.Add('Content-Type', 'application/json')
$headers.Add('Authorization', $auth)

# Get all employees
irm $configuration.BaseUrl -Headers $headers
$ErrorActionPreference = "Stop"

function Get-FileFromInternet {
    param (
        $url,
        $sha512,
        $path
    )

    $temporary = New-TemporaryFile

    if (Test-Path $path) {
        # it's in cache
        Remove-Item $temporary -ErrorAction Ignore
        Move-Item $path $temporary
    }
    else
    {
        Invoke-WebRequest -OutFile $temporary -Uri "$url"
    }

    # check hash
    $actual_hash = (Get-FileHash $temporary -Algorithm SHA512).Hash
    if ($actual_hash.ToUpper() -eq $sha512.ToUpper())
    {
        Move-Item $temporary $path
    }
    else
    {
        "Hash check failed - file $url had hash $sha512, should be $actual_hash" | Write-Debug
        throw "Hash check failed"
    }
}

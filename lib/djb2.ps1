$members = @'
public static int djb2(string str)
{
    unchecked
    {
        int hash = 5381;
        foreach(char ch in str)
        {
            hash = (hash << 5) + hash + ch;
        }

        return hash;
    }
}
'@

$type = Add-Type -Name "djb2impl" -Namespace "djb2" -MemberDefinition $members -PassThru;

function djb2 {
    param (
        [Parameter(Mandatory)]
        [string]
        $Data
    )

    $header = $Data.IndexOf("/*<djb2:")
    if ($header -lt 0)
    {
        return $Data
    }
    $textBegin = $header + "/*<djb2:".Length

    $textEnd = $Data.IndexOf(">*/", $textBegin) - 1
    $text = $Data.Substring($textBegin, $textEnd - $textBegin + 1)
    $end = $Data.IndexOf("/*</djb2>*/")

    $hash = [djb2.djb2impl]::djb2($text)
    $hashHex = "0x" + $hash.ToString("X8")

    Write-Warning "djb2 text $text -> $hashHex"

    return $Data.Substring(0, $textEnd + 4) + $hashHex + $Data.Substring($end)
}

$lines = [System.IO.File]::ReadAllLines($args[0])
$myline = [System.Collections.Generic.List[string]]::new()
foreach($line in $lines)
{
    if ($line.Length -gt 0)
    {
        $line = djb2 $line
    }

    $myline.Add($line)
}

[System.IO.File]::WriteAllLines($args[0], $myline.ToArray())

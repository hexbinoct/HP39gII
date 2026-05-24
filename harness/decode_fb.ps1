# Decode HP 39gII framebuffer dump into a viewable PGM image.
# Encoding (deduced from FUN_009462d0): 86 bytes/row, 256 pixels/row.
# Each byte = 3 packed pixels: bits 7-5 = pix0 (3-bit), bits 4-2 = pix1 (3-bit), bits 1-0 = pix2 (2-bit, shifted left 1).
# Display = pixel >> 1 → 4 grayscale levels (0..3).
# We map level 0..3 → 0/85/170/255 for visual contrast (matches calc palette 0x000000 / 0x555555 / 0xAAAAAA / 0xFFFFFF).
param(
    [Parameter(Mandatory=$true)] [string]$Bin,
    [string]$Pgm = $null
)
if (-not $Pgm) { $Pgm = [System.IO.Path]::ChangeExtension($Bin, '.pgm') }
$bytes = [System.IO.File]::ReadAllBytes($Bin)
$width = 256; $height = 127; $pitch = 86
if ($bytes.Length -ne $height * $pitch) { Write-Error "expected $($height*$pitch) bytes, got $($bytes.Length)"; exit 1 }

$grayMap = @(0, 85, 170, 255)
$out = New-Object byte[] ($width * $height)
for ($y = 0; $y -lt $height; $y++) {
    $rowStart = $y * $pitch
    $outStart = $y * $width
    for ($bx = 0; $bx -lt $pitch; $bx++) {
        $b = $bytes[$rowStart + $bx]
        $p0 = ($b -shr 5) -band 7
        $p1 = ($b -shr 2) -band 7
        $p2 = (($b -band 3) -shl 1)
        $level0 = $p0 -shr 1
        $level1 = $p1 -shr 1
        $level2 = $p2 -shr 1
        $x = $bx * 3
        if ($x     -lt $width) { $out[$outStart + $x    ] = $grayMap[$level0] }
        if ($x + 1 -lt $width) { $out[$outStart + $x + 1] = $grayMap[$level1] }
        if ($x + 2 -lt $width) { $out[$outStart + $x + 2] = $grayMap[$level2] }
    }
}

$header = "P5`n$width $height`n255`n"
$headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
$fs = [System.IO.File]::Create($Pgm)
$fs.Write($headerBytes, 0, $headerBytes.Length)
$fs.Write($out, 0, $out.Length)
$fs.Close()
Write-Output "wrote $Pgm ($($out.Length) px)"

# Also do an ASCII preview using 4 shades for quick eyeball verification.
$shades = @(' ', '.', 'o', '#')
$asciiLines = @()
for ($y = 0; $y -lt $height; $y++) {
    $sb = New-Object System.Text.StringBuilder
    for ($bx = 0; $bx -lt $pitch; $bx++) {
        $b = $bytes[$y*$pitch + $bx]
        $p0 = (($b -shr 5) -band 7) -shr 1
        $p1 = (($b -shr 2) -band 7) -shr 1
        $p2 = ((($b -band 3) -shl 1)) -shr 1
        [void]$sb.Append($shades[$p0])
        [void]$sb.Append($shades[$p1])
        [void]$sb.Append($shades[$p2])
    }
    $asciiLines += $sb.ToString().Substring(0, [Math]::Min($width, $sb.Length))
}
$asciiOut = [System.IO.Path]::ChangeExtension($Bin, '.txt')
$asciiLines | Set-Content -Encoding ASCII $asciiOut
Write-Output "wrote $asciiOut ($height lines)"

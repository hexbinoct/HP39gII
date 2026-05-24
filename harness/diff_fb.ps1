# Visualize the diff between two framebuffer dumps using the same 3+3+2 decoding.
# Pixels unchanged → ' '. Pixels that appeared in B → '#'. Pixels that disappeared from B → '.'.
param([Parameter(Mandatory=$true)][string]$A, [Parameter(Mandatory=$true)][string]$B)

$ba = [System.IO.File]::ReadAllBytes($A)
$bb = [System.IO.File]::ReadAllBytes($B)
$width = 256; $height = 127; $pitch = 86
$shadesA = New-Object byte[] ($width * $height)
$shadesB = New-Object byte[] ($width * $height)

function Unpack {
    param($bytes, $out)
    for ($y = 0; $y -lt $height; $y++) {
        for ($bx = 0; $bx -lt $pitch; $bx++) {
            $b = $bytes[$y*$pitch + $bx]
            $p0 = (($b -shr 5) -band 7) -shr 1
            $p1 = (($b -shr 2) -band 7) -shr 1
            $p2 = ((($b -band 3) -shl 1)) -shr 1
            $x = $bx * 3
            if ($x   -lt $width) { $out[$y*$width + $x  ] = $p0 }
            if ($x+1 -lt $width) { $out[$y*$width + $x+1] = $p1 }
            if ($x+2 -lt $width) { $out[$y*$width + $x+2] = $p2 }
        }
    }
}
Unpack $ba $shadesA
Unpack $bb $shadesB

# Find bounding box of change (skip noisy global "annunciator row" updates: focus on calc display area)
$minX = $width; $minY = $height; $maxX = 0; $maxY = 0; $changed = 0
for ($y = 0; $y -lt $height; $y++) {
    for ($x = 0; $x -lt $width; $x++) {
        $i = $y * $width + $x
        if ($shadesA[$i] -ne $shadesB[$i]) {
            $changed++
            if ($x -lt $minX) { $minX = $x }
            if ($x -gt $maxX) { $maxX = $x }
            if ($y -lt $minY) { $minY = $y }
            if ($y -gt $maxY) { $maxY = $y }
        }
    }
}
Write-Output ("changed pixels: {0}  bbox: x={1}..{2} y={3}..{4}" -f $changed, $minX, $maxX, $minY, $maxY)
if ($changed -eq 0) { return }

# Print the diff region (full image width, but only the rows that contain changes)
for ($y = [Math]::Max(0, $minY - 1); $y -le [Math]::Min($height-1, $maxY + 1); $y++) {
    $sb = New-Object System.Text.StringBuilder
    for ($x = 0; $x -lt $width; $x++) {
        $i = $y * $width + $x
        $a = $shadesA[$i]; $b = $shadesB[$i]
        if ($a -eq $b) {
            # unchanged - render dimly as ' ' or '.'
            if ($b -eq 0) { [void]$sb.Append(' ') }
            elseif ($b -le 2) { [void]$sb.Append('.') }
            else { [void]$sb.Append(':') }
        } else {
            # changed
            if ($b -gt $a) { [void]$sb.Append('#') }  # got darker (ink appeared)
            else           { [void]$sb.Append('o') }  # got lighter (ink disappeared)
        }
    }
    Write-Output ('|' + $sb.ToString() + '|')
}

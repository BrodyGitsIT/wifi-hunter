# Wi‑Fi AP Hunter — Collapsed 3‑Panel Analyzer (per AP / BSSID Mask)



$Host.UI.RawUI.WindowTitle = "Wi-Fi AP Hunter"

try {

  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

  $OutputEncoding = [System.Text.Encoding]::UTF8

} catch {}



# ---- Native WiFi API for forced scanning ----

Add-Type -TypeDefinition @"

using System;

using System.Runtime.InteropServices;

public class WlanAPI {

  [DllImport("wlanapi.dll", SetLastError = true)]

  public static extern int WlanOpenHandle(int v, IntPtr r, out int nv, out IntPtr h);

  [DllImport("wlanapi.dll", SetLastError = true)]

  public static extern int WlanCloseHandle(IntPtr h, IntPtr r);

  [DllImport("wlanapi.dll", SetLastError = true)]

  public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list);

  [DllImport("wlanapi.dll", SetLastError = true)]

  public static extern int WlanScan(IntPtr h, ref Guid g, IntPtr s, IntPtr ie, IntPtr r);

  [DllImport("wlanapi.dll", SetLastError = true)]

  public static extern void WlanFreeMemory(IntPtr p);

}

"@



function Invoke-WlanScan {

  $ver = 0

  $handle = [IntPtr]::Zero

  $rc = [WlanAPI]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$handle)

  if ($rc -ne 0) { return }

  $ifList = [IntPtr]::Zero

  $rc = [WlanAPI]::WlanEnumInterfaces($handle, [IntPtr]::Zero, [ref]$ifList)

  if ($rc -ne 0) { [WlanAPI]::WlanCloseHandle($handle, [IntPtr]::Zero) | Out-Null; return }

  $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($ifList, 0)

  if ($count -gt 0) {

    $guidBytes = New-Object byte[] 16

    [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($ifList.ToInt64() + 8), $guidBytes, 0, 16)

    $guid = New-Object System.Guid(,$guidBytes)

    [WlanAPI]::WlanScan($handle, [ref]$guid, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

  }

  [WlanAPI]::WlanFreeMemory($ifList)

  [WlanAPI]::WlanCloseHandle($handle, [IntPtr]::Zero) | Out-Null

}



# ---- Wi-Fi parsing ----

function Get-SSIDList {

  netsh wlan show networks |

    Select-String "^SSID\s+\d+\s*:" |

    ForEach-Object { ($_ -split ":\s*",2)[1].Trim() } |

    Where-Object { $_ -and $_ -ne "Hidden Network" } |

    Sort-Object -Unique

}



function Get-AllSignals($targetSSID) {

  $raw = netsh wlan show networks mode=bssid

  $inSSID = $false

  $bssid = ""

  $results = @{}

  foreach ($line in $raw) {

    if ($line -match "^SSID\s+\d+\s*:\s*(.*)") { $inSSID = ($Matches[1].Trim() -eq $targetSSID); continue }

    if ($inSSID -and $line -match "BSSID\s+\d+\s*:\s+(.+)") { $bssid = $Matches[1].Trim(); continue }

    if ($inSSID -and $bssid -and $line -match "Signal\s*:\s*(\d+)%") {

      $sig = [int]$Matches[1]

      if ($sig -ge 99) { $sig = 100 }

      $results[$bssid] = $sig

      $bssid = ""

    }

  }

  return $results

}



# ---- Location permission check ----

function Test-LocationPermission {

  # Returns $true if netsh can return data, $false if blocked by location policy.

  $out = netsh wlan show networks 2>&1 | Out-String

  return ($out -notmatch "location permission" -and $out -notmatch "Access is denied")

}



function Assert-LocationPermission {

  if (Test-LocationPermission) { return }



  Write-Host ""

  Write-Host "  LOCATION PERMISSION REQUIRED" -ForegroundColor Yellow

  Write-Host "  Windows 11 blocks Wi-Fi network details (BSSIDs / signal)" -ForegroundColor Yellow

  Write-Host "  until Location Services is enabled in Privacy settings." -ForegroundColor Yellow

  Write-Host ""

  Write-Host "  Would you like to open the Location settings page now? [Y/N] " -ForegroundColor Cyan -NoNewline

  $ans = (Read-Host).Trim().ToUpper()



  if ($ans -eq 'Y') {

    Write-Host ""

    Write-Host "  Opening ms-settings:privacy-location ..." -ForegroundColor Green

    Start-Process "ms-settings:privacy-location"

    Write-Host ""

    Write-Host "  Steps:" -ForegroundColor White

    Write-Host "    1. Turn ON  'Location services'" -ForegroundColor White

    Write-Host "    2. Scroll down, turn ON  'Let desktop apps access your location'" -ForegroundColor White

    Write-Host "    3. Come back here -- we'll check every 3 seconds automatically." -ForegroundColor White

    Write-Host ""



    $dots = 0

    while (-not (Test-LocationPermission)) {

      $dots++

      Write-Host ("`r  Waiting for permission" + ('.' * ($dots % 4)).PadRight(4)) -NoNewline -ForegroundColor DarkGray

      Start-Sleep 3

    }

    Write-Host "`r  Location permission detected! Continuing...         " -ForegroundColor Green

    Start-Sleep 1

  } else {

    Write-Host ""

    Write-Host "  Manual fix: Settings > Privacy & security > Location" -ForegroundColor DarkGray

    Write-Host "  Enable 'Location services' and 'Let desktop apps access your location'." -ForegroundColor DarkGray

    Write-Host ""

    Write-Host "  Exiting. Re-run the script after enabling location." -ForegroundColor Yellow

    exit 1

  }

}



# ---- Helpers ----

function Get-Mask($bssid) {

  $p = $bssid -split ':'

  if ($p.Count -ge 4) { return ($p[0..3] -join ':') }

  return $bssid

}



function Short-Id($bssid) {

  $p = $bssid -split ':'

  if ($p.Count -ge 2) { return ($p[-2] + ':' + $p[-1]).ToUpper() }

  return $bssid.ToUpper()

}



function Get-Trend($hist) {

  if ($hist.Count -lt 3) { return "" }

  $recent = $hist[($hist.Count-3)..($hist.Count-1)]

  $diff = $recent[2] - $recent[0]

  if ($diff -ge 10) { return ([char]0x25B2 + " rising") }

  elseif ($diff -ge 3) { return ([char]0x2197 + " rising") }

  elseif ($diff -le -10) { return ([char]0x25BC + " falling") }

  elseif ($diff -le -3) { return ([char]0x2198 + " falling") }

  else { return ([char]0x2192 + " steady") }

}



function Get-LevelIcon($sig) {

  if ($sig -le 0)  { return "??" }

  if ($sig -lt 25) { return "[ICE]" }

  if ($sig -lt 50) { return "[COLD]" }

  if ($sig -lt 75) { return "[WARM]" }

  return "[HOT]"

}



function Get-StatusText($sig) {

  if ($sig -le 0)   { return "NOT SEEN" }

  if ($sig -ge 100) { return "VERY HOT -- YOU ARE THERE" }

  if ($sig -ge 75)  { return "HOT" }

  if ($sig -ge 50)  { return "WARM" }

  if ($sig -ge 25)  { return "COLD" }

  return "ICE"

}



function Get-LevelColor($sig) {

  if ($sig -le 0)  { return "DarkGray" }

  if ($sig -lt 25) { return "Cyan" }

  if ($sig -lt 50) { return "Blue" }

  if ($sig -lt 75) { return "Yellow" }

  return "Red"

}



function Get-WindowWidth {

  try { $w = $Host.UI.RawUI.WindowSize.Width; if ($w -gt 20) { return $w } } catch {}

  return 120

}



# Write exactly one terminal line, always padded/truncated to (windowWidth-1)

# so it overwrites whatever was there before — no leftover characters.

function Write-Line([string]$text, [string]$color) {

  $w = Get-WindowWidth

  $t = if ($text.Length -gt ($w - 1)) { $text.Substring(0, $w - 1) } else { $text.PadRight($w - 1) }

  if ([string]::IsNullOrWhiteSpace($color)) { Write-Host $t }

  else { Write-Host $t -ForegroundColor $color }

}



$bssidColors = @("Green","Cyan","Magenta","Yellow","Blue","White","DarkYellow","DarkCyan")

$SeriesMarkers = @([char]0x25CF,[char]0x25A0,[char]0x25B2,[char]0x25C6,[char]0x25CB,[char]0x2715,[char]0x25D0,[char]0x25D1)

function Get-BSSIDColor($i) { return $bssidColors[$i % $bssidColors.Count] }

function Get-Marker($i) { return $SeriesMarkers[$i % $SeriesMarkers.Count] }



# ---- Graph rendering ----

# $maxPoints controls how many columns the graph has — caller passes this in

# so all three panels fit side-by-side.



function Render-Graph($hist, $maxPoints) {

  $data = if ($hist.Count -gt $maxPoints) { $hist[($hist.Count-$maxPoints)..($hist.Count-1)] } else { $hist }



  $minVal = 100; $maxVal = 0; $hasData = $false

  foreach ($v in $data) {

    if ($v -gt 0) {

      $hasData = $true

      if ($v -lt $minVal) { $minVal = $v }

      if ($v -gt $maxVal) { $maxVal = $v }

    }

  }



  if (-not $hasData) { return ,@("  (no signal)") }





  $spread = $maxVal - $minVal

  $step = if ($spread -le 20) { 5 } else { 10 }

  $graphMin = $minVal - ($minVal % $step) - $step

  $graphMax = $maxVal - ($maxVal % $step) + $step + $step

  if ($graphMin -lt 0) { $graphMin = 0 }

  if ($graphMax -gt 100) { $graphMax = 100 }



  $vline=[char]0x2502; $hline=[char]0x2500; $corner=[char]0x2514; $dot=[char]0x25CF

  $lines = New-Object System.Collections.Generic.List[string]



  for ($pct=$graphMax; $pct -ge $graphMin; $pct-=$step) {

    $s = ("{0,4}%{1}" -f $pct, $vline)

    for ($col=0; $col -lt $data.Count; $col++) {

      $val = $data[$col]

      if ($val -le 0) { $s += ' '; continue }

      $rem = $val % $step

      $snap = if ($rem*2 -ge $step) { $val - $rem + $step } else { $val - $rem }

      $s += if ($snap -eq $pct) { $dot } else { ' ' }

    }

    $lines.Add($s)

  }

  $xAxis = "     {0}{1}" -f $corner, ([string]$hline * $data.Count)

  $lines.Add($xAxis)



  # Time label: keep it exactly $maxPoints wide in the data area

  $lbl = " oldest"

  $arrow = "> now"

  $dataWidth = $maxPoints

  $mid = $dataWidth - $lbl.Length - $arrow.Length

  if ($mid -lt 1) { $mid = 1 }

  $timeLine = "      " + $lbl + ([string]$hline * $mid) + $arrow

  $lines.Add($timeLine)



  return ,$lines.ToArray()

}



# ---- Side-by-side panel printer ----

# KEY FIX: each panel is rendered at a fixed $colW width so the total never

# exceeds terminal width.  Lines are truncated/padded to $colW before printing.

function Print-Panels($panelA, $colorA, $panelB, $colorB, $panelC, $colorC, $colW, $pad=3) {

  $rows = @($panelA.Count, $panelB.Count, $panelC.Count) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum

  $space = ' ' * $pad



  for ($i=0; $i -lt $rows; $i++) {

    [string]$a = if ($i -lt $panelA.Count) { $panelA[$i] } else { '' }

    [string]$b = if ($i -lt $panelB.Count) { $panelB[$i] } else { '' }

    [string]$c = if ($i -lt $panelC.Count) { $panelC[$i] } else { '' }



    # Truncate if over budget, then pad to exactly $colW

    $a = if ($a.Length -gt $colW) { $a.Substring(0,$colW) } else { $a.PadRight($colW) }

    $b = if ($b.Length -gt $colW) { $b.Substring(0,$colW) } else { $b.PadRight($colW) }

    $c = if ($c.Length -gt $colW) { $c.Substring(0,$colW) } else { $c.PadRight($colW) }



    Write-Host -NoNewline $a -ForegroundColor $colorA

    Write-Host -NoNewline $space

    Write-Host -NoNewline $b -ForegroundColor $colorB

    Write-Host -NoNewline $space

    Write-Host $c -ForegroundColor $colorC

  }

}



# Compute safe per-panel column width and graph data points from terminal width

function Get-PanelLayout {

  $w = Get-WindowWidth

  $pad = 3          # gap between panels

  $axisPrefix = 6   # "  95%|" prefix chars

  $totalPad = $pad * 2

  # available data columns: w split 3 ways minus axis prefixes and padding

  $colW = [int](($w - $totalPad) / 3)

  if ($colW -lt 20) { $colW = 20 }

  $dataPoints = $colW - $axisPrefix

  if ($dataPoints -lt 4) { $dataPoints = 4 }

  if ($dataPoints -gt 40) { $dataPoints = 40 }

  return @{ ColW = $colW; DataPoints = $dataPoints }

}



# ----- MAIN -----



# Check location permission first — required on Windows 11 for netsh BSSID data

Assert-LocationPermission



$ssids = Get-SSIDList

if (-not $ssids) { Write-Host "No SSIDs detected. Is Wi-Fi enabled?" -ForegroundColor Yellow; exit }



Write-Host "Select SSID:" -ForegroundColor Cyan

for ($i=0; $i -lt $ssids.Count; $i++) { Write-Host ("[{0}] {1}" -f $i, $ssids[$i]) }

$choice = Read-Host "Enter number"

$targetSSID = $ssids[[int]$choice]



$renderEvery   = 1

$scanTick      = 0

$MaxMasksToShow = 8



# Pre-calculate how many blank lines one mask block uses so we can

# blank the whole screen before drawing (avoids ghost lines when

# fewer masks are visible than last frame).

$linesPerMaskBlock = 0   # computed dynamically each frame



Write-Host "`nHunting: $targetSSID  (Ctrl+C to stop)" -ForegroundColor Green

Start-Sleep 1

Clear-Host



$oldCursorVisible = $true

try { $oldCursorVisible = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch {}



# State

$maskHistory    = @{}

$maskPeaks      = @{}

$maskMaxHist    = @{}

$maskOrder      = [System.Collections.ArrayList]@()

$maskBssidOrder = @{}

$globalTicks    = 0



# Track how many lines were printed last frame so we can overwrite them all

$lastFrameLines = 0



try {

  while ($true) {

    Invoke-WlanScan

    Start-Sleep -Milliseconds 300

    $signals = Get-AllSignals $targetSSID

    $globalTicks++



    foreach ($b in $signals.Keys) {

      $mask = Get-Mask $b

      if (-not $maskHistory.ContainsKey($mask)) {

        $maskHistory[$mask]    = @{}

        $maskPeaks[$mask]      = @{}

        $maskMaxHist[$mask]    = [System.Collections.ArrayList]@()

        $maskBssidOrder[$mask] = [System.Collections.ArrayList]@()

        $null = $maskOrder.Add($mask)

      }

      if (-not $maskHistory[$mask].ContainsKey($b)) {

        $maskHistory[$mask][$b] = [System.Collections.ArrayList]@()

        $maskPeaks[$mask][$b]   = 0

        $null = $maskBssidOrder[$mask].Add($b)

        for ($z=0; $z -lt ($globalTicks - 1); $z++) { $null = $maskHistory[$mask][$b].Add(0) }

      }

    }



    foreach ($mask in $maskOrder) {

      $maxNow = 0

      foreach ($b in $maskBssidOrder[$mask]) {

        $sig = 0

        if ($signals.ContainsKey($b)) { $sig = $signals[$b] }

        $null = $maskHistory[$mask][$b].Add($sig)

        if ($sig -gt $maskPeaks[$mask][$b]) { $maskPeaks[$mask][$b] = $sig }

        if ($sig -gt $maxNow) { $maxNow = $sig }

      }

      $null = $maskMaxHist[$mask].Add($maxNow)

    }



    $scanTick++

    if ($scanTick % $renderEvery -ne 0) { Start-Sleep -Milliseconds 150; continue }



    # -- Build frame into a string list, then write it atomically --------

    $layout = Get-PanelLayout

    $colW   = $layout.ColW

    $pts    = $layout.DataPoints



    $frame = [System.Collections.Generic.List[object]]@()  # each entry: @{Text;Color}

    function FAdd([string]$t, [string]$c) { $frame.Add([pscustomobject]@{Text=$t;Color=$c}) }



    $ts = (Get-Date).ToString('HH:mm:ss')

    FAdd ("Wi-Fi AP Hunter   SSID: {0}   {1}   Ctrl+C to stop" -f $targetSSID, $ts) "Cyan"

    FAdd ("=" * (Get-WindowWidth - 1)) "DarkGray"



    $maskRank = @()

    foreach ($mask in $maskOrder) {

      $mh = $maskMaxHist[$mask]

      $nowBest = if ($mh.Count -gt 0) { [int]$mh[$mh.Count-1] } else { 0 }

      $maskRank += [pscustomobject]@{ Mask=$mask; Now=$nowBest }

    }

    $maskRank = $maskRank | Sort-Object Now -Descending



    $shown = 0

    foreach ($mr in $maskRank) {

      if ($shown -ge $MaxMasksToShow) { break }

      $mask = $mr.Mask

      $seriesOrder = $maskBssidOrder[$mask]

      if ($seriesOrder.Count -eq 0) { continue }



      $idxMap = @{}

      for ($i=0; $i -lt $seriesOrder.Count; $i++) { $idxMap[$seriesOrder[$i]] = $i }



      $bRank = @()

      foreach ($b in $seriesOrder) {

        $h = $maskHistory[$mask][$b]

        $bRank += [pscustomobject]@{ BSSID=$b; Now=[int]$h[$h.Count-1] }

      }

      $bRank = $bRank | Sort-Object Now -Descending



      $b1 = $bRank[0].BSSID

      $b2 = if ($bRank.Count -gt 1) { $bRank[1].BSSID } else { $bRank[0].BSSID }



      $nowMask = [int]$bRank[0].Now

      $pkMask = 0

      foreach ($b in $seriesOrder) { if ($maskPeaks[$mask][$b] -gt $pkMask) { $pkMask = $maskPeaks[$mask][$b] } }



      $icon   = Get-LevelIcon $nowMask

      $status = Get-StatusText $nowMask

      FAdd ("Mask: {0}  ({1} radios)" -f $mask, $seriesOrder.Count) "Cyan"

      FAdd ("  {0}  Strongest now: {1}%   Peak: {2}%   [{3}]" -f $icon, $nowMask, $pkMask, $status) (Get-LevelColor $nowMask)



      foreach ($row in $bRank) {

        $b   = $row.BSSID

        $now = [int]$row.Now

        $pk  = $maskPeaks[$mask][$b]

        $trend  = Get-Trend $maskHistory[$mask][$b]

        $marker = Get-Marker $idxMap[$b]

        FAdd ("  {0} {1}  Now: {2,3}%   Peak: {3,3}%   {4}" -f $marker, $b, $now, $pk, $trend) (Get-LevelColor $now)

      }



      FAdd "" ""



      $pCollapsed = Render-Graph $maskMaxHist[$mask]          $pts

      $pTop1      = Render-Graph $maskHistory[$mask][$b1]     $pts

      $pTop2      = Render-Graph $maskHistory[$mask][$b2]     $pts



      $c1 = Get-BSSIDColor $idxMap[$b1]

      $c2 = Get-BSSIDColor $idxMap[$b2]



      # Label line

      $lbl = "[Mask max]   [Top1] {0}   [Top2] {1}" -f $b1, $b2

      FAdd $lbl "DarkGray"



      # Panels — store as a special marker so we flush them together

      $frame.Add([pscustomobject]@{

        IsPanels=$true

        PA=$pCollapsed; CA='White'

        PB=$pTop1;      CB=$c1

        PC=$pTop2;      CC=$c2

        ColW=$colW

      })



      # HUD

      $hud = ""

      foreach ($row in $bRank) {

        $b  = $row.BSSID

        $n  = [int]$row.Now

        $ic = Get-LevelIcon $n

        $hud += ("{0} {1} {2,3}%   " -f $ic, (Short-Id $b), $n)

      }

      FAdd ("  HUD: " + $hud) "DarkGray"

      FAdd "" ""



      $shown++

    }



    # ---- Render frame ----

    # Reset cursor to top-left

    [Console]::SetCursorPosition(0,0)

    $linesWritten = 0

    $winW = Get-WindowWidth



    foreach ($entry in $frame) {

      if ($entry.IsPanels) {

        # Compute rows needed

        $rows = @($entry.PA.Count,$entry.PB.Count,$entry.PC.Count) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum

        $pad = 3

        $cw  = $entry.ColW

        for ($i=0; $i -lt $rows; $i++) {



          [string]$a = if ($i -lt $entry.PA.Count) { $entry.PA[$i] } else { '' }

          [string]$b = if ($i -lt $entry.PB.Count) { $entry.PB[$i] } else { '' }

          [string]$c = if ($i -lt $entry.PC.Count) { $entry.PC[$i] } else { '' }

          $a = if ($a.Length -gt $cw) { $a.Substring(0,$cw) } else { $a.PadRight($cw) }

          $b = if ($b.Length -gt $cw) { $b.Substring(0,$cw) } else { $b.PadRight($cw) }

          $c = if ($c.Length -gt $cw) { $c.Substring(0,$cw) } else { $c.PadRight($cw) }

          $full = $a + (' ' * $pad) + $b + (' ' * $pad) + $c

          # Pad/truncate to window width to erase leftover chars

          if ($full.Length -gt ($winW-1)) { $full = $full.Substring(0,$winW-1) }

          else { $full = $full.PadRight($winW-1) }

          Write-Host $full -ForegroundColor $entry.CA   # axis color for whole line; colors already set per segment above

          # Re-write with per-segment colors:

          # Actually write three segments with proper colors:

          [Console]::CursorLeft = 0

          if ($linesWritten -gt 0) { [Console]::CursorTop = [Console]::CursorTop - 1 }

          # Use Write-Host segments:

          Write-Host -NoNewline $a -ForegroundColor $entry.CA

          Write-Host -NoNewline (' ' * $pad)

          Write-Host -NoNewline $b -ForegroundColor $entry.CB

          Write-Host -NoNewline (' ' * $pad)

          # last segment: pad to fill remaining terminal width to erase old chars

          $remaining = $winW - 1 - $cw - $pad - $cw - $pad

          if ($remaining -lt 0) { $remaining = 0 }

          $cPadded = if ($c.Length -gt $remaining) { $c.Substring(0,$remaining) } else { $c.PadRight($remaining) }

          Write-Host $cPadded -ForegroundColor $entry.CC

          $linesWritten++

        }

      } else {

        $t = $entry.Text

        if ($t.Length -gt ($winW-1)) { $t = $t.Substring(0,$winW-1) }

        $t = $t.PadRight($winW-1)

        if ([string]::IsNullOrWhiteSpace($entry.Color)) { Write-Host $t }

        else { Write-Host $t -ForegroundColor $entry.Color }

        $linesWritten++

      }

    }



    # Erase any leftover lines from a taller previous frame

    $termH = try { $Host.UI.RawUI.WindowSize.Height } catch { 50 }

    $blankLine = ' ' * ($winW - 1)

    while ($linesWritten -lt $lastFrameLines -and [Console]::CursorTop -lt ($termH - 2)) {

      Write-Host $blankLine

      $linesWritten++

    }

    $lastFrameLines = $linesWritten



    Start-Sleep -Milliseconds 250

  }

}

finally {

  try { [Console]::CursorVisible = $oldCursorVisible } catch {}

}

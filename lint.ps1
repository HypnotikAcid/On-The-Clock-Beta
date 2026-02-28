$builtins = @('print', 'len', 'str', 'int', 'float', 'bool', 'dict', 'list', 'set', 'isinstance', 'round', 'hasattr', 'getattr', 'super', 'type', 'range', 'enumerate', 'zip', 'Exception', 'ValueError', 'TypeError', 'KeyError', 'IndexError', 'open')

$files = Get-ChildItem C:\Dev\TimeWarden\web\routes\*.py
foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw
    
    # 1. Get defined functions
    $defined = @()
    $defMatches = [regex]::Matches($content, 'def\s+([A-Za-z_]\w*)\s*\(')
    foreach ($m in $defMatches) { $defined += $m.Groups[1].Value }
    
    # 2. Get imported functions/classes
    $imported = @()
    # Handle single line imports
    $importMatches = [regex]::Matches($content, 'import\s+([A-Za-z_][\w\s,]+)')
    foreach ($m in $importMatches) { 
        $parts = $m.Groups[1].Value -split ','
        foreach ($p in $parts) {
            $clean = $p.Trim() -replace '\s+as\s+\w+', ''
            $imported += $clean
        }
    }
    
    # Handle from imports (multi-line supported with a hack)
    $fromMatches = [regex]::Matches($content, 'from\s+[\w.]+\s+import\s+\(([\s\S]*?)\)')
    foreach ($m in $fromMatches) {
        $parts = $m.Groups[1].Value -split ','
        foreach ($p in $parts) {
            $clean = ($p -replace '\s+', '').Trim()
            if ($clean) { $imported += $clean }
        }
    }
    $fromSingle = [regex]::Matches($content, 'from\s+[\w.]+\s+import\s+(?!\()([^\n]+)')
    foreach ($m in $fromSingle) {
        $parts = $m.Groups[1].Value -split ','
        foreach ($p in $parts) {
            $clean = ($p -replace '\s+as\s+\w+', '').Trim()
            if ($clean) { $imported += $clean }
        }
    }

    # 3. Get bare function calls
    $called = @()
    $callMatches = [regex]::Matches($content, '(?:^|[^\w.])([A-Za-z_]\w*)\s*\(')
    foreach ($m in $callMatches) { 
        $name = $m.Groups[1].Value
        # filter out keywords that look like calls
        if ($name -notin @('if', 'elif', 'while', 'for', 'return', 'yield', 'and', 'or', 'not', 'in', 'is')) {
            $called += $name
        }
    }
    
    $called = $called | Sort-Object -Unique
    
    $missing = @()
    foreach ($c in $called) {
        if ($c -notin $builtins -and $c -notin $defined -and $c -notin $imported) {
            $missing += $c
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-Host "$($file.Name) Potential Missing References:"
        Write-Host ($missing -join ', ')
    }
}

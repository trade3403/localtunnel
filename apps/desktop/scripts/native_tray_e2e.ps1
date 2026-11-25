param(
    [Parameter(Mandatory=$true)][int]$ProcessId,
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][ValidateSet('show','stop','quit')][string]$Action
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Native tray test is restricted to disposable GitHub-hosted Windows runners'
}
$process = Get-Process -Id $ProcessId -ErrorAction Stop
if ($process.Path -ne (Resolve-Path -LiteralPath $Executable).Path) { throw 'Unexpected tray process image' }
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class LocalTunnelTrayTest {
    public delegate bool EnumProc(IntPtr h, IntPtr arg);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int left, top, right, bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int x, y; }
    [StructLayout(LayoutKind.Sequential)] public struct NOTIFYICONIDENTIFIER {
        public uint cbSize; public IntPtr hWnd; public uint uID; public Guid guidItem;
    }
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr arg);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder name, int count);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll", SetLastError=true)] static extern IntPtr SendMessageTimeout(IntPtr h,uint msg,IntPtr wp,IntPtr lp,uint flags,uint timeout,out UIntPtr result);
    [DllImport("user32.dll")] static extern int GetMenuItemCount(IntPtr menu);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetMenuString(IntPtr menu,uint item,StringBuilder text,int length,uint flags);
    [DllImport("user32.dll")] static extern bool GetMenuItemRect(IntPtr h,IntPtr menu,uint item,out RECT rect);
    [DllImport("user32.dll")] static extern bool SetCursorPos(int x,int y);
    [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(POINT point);
    [DllImport("user32.dll")] static extern void mouse_event(uint flags,uint dx,uint dy,uint data,UIntPtr extra);
    [DllImport("shell32.dll")] static extern int Shell_NotifyIconGetRect(ref NOTIFYICONIDENTIFIER id,out RECT rect);

    public static IntPtr[] Find(uint pid, string cls, bool visible) {
        var result = new List<IntPtr>();
        EnumWindows(delegate(IntPtr h, IntPtr arg) {
            uint owner; GetWindowThreadProcessId(h,out owner);
            if(owner != pid || (visible && !IsWindowVisible(h))) return true;
            var name = new StringBuilder(128);
            GetClassName(h,name,name.Capacity);
            if(name.ToString()==cls) result.Add(h);
            return true;
        }, IntPtr.Zero);
        return result.ToArray();
    }
    public static uint ThreadId(IntPtr h) { uint owner; return GetWindowThreadProcessId(h,out owner); }
    public static bool OpenMenu(IntPtr h) {
        SetProcessDPIAware();
        // Locked tray-icon 0.25.1 registers a single top-level tray_icon_app
        // HWND and callback message 6002. Verify actual shell registration
        // before delivering the notification-area right-button-up event.
        uint found=0;
        RECT iconRect=new RECT();
        for(uint n=1;n<=16;n++) {
            var id=new NOTIFYICONIDENTIFIER { cbSize=(uint)Marshal.SizeOf(typeof(NOTIFYICONIDENTIFIER)), hWnd=h, uID=n, guidItem=Guid.Empty };
            RECT rect;
            if(Shell_NotifyIconGetRect(ref id,out rect)==0 && rect.right>rect.left && rect.bottom>rect.top) {
                if(found!=0) throw new Exception("multiple registered icons for tray HWND");
                found=n; iconRect=rect;
            }
        }
        if(found==0) return false;
        if(!SetCursorPos((iconRect.left+iconRect.right)/2,(iconRect.top+iconRect.bottom)/2))
            throw new Exception("cannot position cursor at registered tray icon");
        return PostMessage(h,6002,(IntPtr)found,(IntPtr)0x205);
    }
    public static bool SelectMenuItem(IntPtr menuWindow, IntPtr tray, int index) {
        SetProcessDPIAware();
        if(ThreadId(menuWindow)!=ThreadId(tray)) throw new Exception("unexpected popup owner thread");
        UIntPtr result;
        // MN_GETHMENU returns the actual open popup's HMENU.
        if(SendMessageTimeout(menuWindow,0x01E1,IntPtr.Zero,IntPtr.Zero,2,2000,out result)==IntPtr.Zero) return false;
        var menu=new IntPtr(unchecked((long)result.ToUInt64()));
        if(menu==IntPtr.Zero || GetMenuItemCount(menu)!=3) return false;
        string[] expected={"\u663e\u793a\u4e3b\u7a97\u53e3","\u505c\u6b62\u96a7\u9053","\u9000\u51fa LocalTunnel"};
        for(uint i=0;i<3;i++) {
            var name=new StringBuilder(128);
            if(GetMenuString(menu,i,name,name.Capacity,0x400)==0 || name.ToString()!=expected[i])
                throw new Exception("unexpected native popup menu labels");
        }
        RECT rect;
        if(!GetMenuItemRect(IntPtr.Zero,menu,(uint)index,out rect)||rect.right<=rect.left||rect.bottom<=rect.top) return false;
        var pt=new POINT {x=(rect.left+rect.right)/2,y=(rect.top+rect.bottom)/2};
        if(WindowFromPoint(pt)!=menuWindow) return false;
        if(!SetCursorPos(pt.x,pt.y)) throw new Exception("cannot position cursor at native menu item");
        if(WindowFromPoint(pt)!=menuWindow) return false;
        // Actual input on the verified native popup item; no WM_COMMAND,
        // no direct Rust handler invocation, and no product test hooks.
        mouse_event(2,0,0,0,UIntPtr.Zero);
        mouse_event(4,0,0,0,UIntPtr.Zero);
        return true;
    }
}
'@
$deadline = [DateTime]::UtcNow.AddSeconds(15)
$tray = [IntPtr]::Zero
do {
    $windows = @([LocalTunnelTrayTest]::Find([uint32]$ProcessId,'tray_icon_app',$false))
    if ($windows.Count -gt 1) { throw 'Multiple tray windows in test process' }
    if ($windows.Count -eq 1) { $tray = $windows[0]; break }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)
if ($tray -eq [IntPtr]::Zero) { throw 'Native tray window not found' }
if (@([LocalTunnelTrayTest]::Find([uint32]$ProcessId,'#32768',$true)).Count -ne 0) {
    throw 'Unexpected pre-existing application popup'
}
if (![LocalTunnelTrayTest]::OpenMenu($tray)) { throw 'Tray icon is not registered with the Windows shell or notification dispatch failed' }
$index = @{show=0;stop=1;quit=2}[$Action]
$deadline = [DateTime]::UtcNow.AddSeconds(12)
do {
    $popups = @([LocalTunnelTrayTest]::Find([uint32]$ProcessId,'#32768',$true))
    if ($popups.Count -gt 1) { throw 'Multiple native popups in test process' }
    if ($popups.Count -eq 1 -and [LocalTunnelTrayTest]::SelectMenuItem($popups[0],$tray,$index)) {
        [Console]::WriteLine("native tray menu item clicked: $Action")
        exit 0
    }
    Start-Sleep -Milliseconds 200
} while ([DateTime]::UtcNow -lt $deadline)
throw "Native tray menu item not clickable: $Action"

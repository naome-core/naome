param([uint32] $TargetProcessId, [uint32] $EventKind)
$ErrorActionPreference = 'Stop'

# This helper joins only the verifier's isolated CREATE_NEW_CONSOLE console.
# No event is sent until the membership check excludes Cargo and other owners.
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class VerifierConsoleSignal {
    private delegate bool Handler(uint kind);
    private static readonly Handler Ignore = kind => kind == 0 || kind == 1;
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleCtrlHandler(Handler handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleProcessList([Out] uint[] processes, uint capacity);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GenerateConsoleCtrlEvent(uint kind, uint group);

    public static int Send(uint targetId, uint kind) {
        if (kind > 1) return 10;
        using (Process target = Process.GetProcessById(checked((int)targetId))) {
            // Acquire before generation, so rapid successful exit is harmless.
            IntPtr handle = target.Handle;
            FreeConsole();
            if (!AttachConsole(targetId)) return 11;
            // AttachConsole resets the table: register after attachment.
            if (!SetConsoleCtrlHandler(Ignore, true)) return 12;
            uint[] members = new uint[3];
            uint count = GetConsoleProcessList(members, (uint)members.Length);
            uint ownId = (uint)Process.GetCurrentProcess().Id;
            if (count != 2) return 13;
            if (!((members[0] == ownId && members[1] == targetId)
                || (members[1] == ownId && members[0] == targetId))) return 14;
            if (!GenerateConsoleCtrlEvent(kind, 0)) return 15;
            return target.WaitForExit(10000) ? 0 : 16;
        }
    }
}
'@
exit [VerifierConsoleSignal]::Send($TargetProcessId, $EventKind)

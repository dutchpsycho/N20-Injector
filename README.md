# N20-Injector

A Windows-only proof of concept that demonstrates user-mode DLL injection by installing a runtime trampoline into a hot function inside the target process, plus optional thread-context “teleportation” to immediately execute the injected payload. This repo is intended for research and learning in controlled environments.

---

## Features

* Resolves a target process and a hot API to hook, reads the original bytes, then writes a 64-bit absolute jump trampoline to a code cave in the remote process. 
* Generates position-aware shellcode that restores original bytes, loads a specified DLL, and hands off control safely. 
* Picks a “best” victim thread using the Process Snapshot API and simple heuristics. 
* Optional thread hijack that rewrites RIP and a safe stack candidate to execute immediately at the injected stub (This is WIP and commented out for now as it is extremely unstable)
* Includes a small main program that finds `notepad.exe`, boots the support runtime, and performs the injection end to end. 

---

## How it works

1. **Target discovery**
   The demo program snapshots processes to find `notepad.exe`, measures initialization time for the support runtime, and prepares parameters like the DLL path. 

2. **Remote symbol resolution**
   The injector opens the remote process, locates a target export such as `ntdll!NtWaitForWorkViaWorkerFactory`, and reads the original prologue bytes at that address. A fixed `HOOK_SIZE` of 12 bytes is used on x64 to fit a `mov rax, imm64` + `jmp rax` sequence. 

3. **Remote allocations**
   It allocates writable memory for the DLL path and a separate RX region for the generated shellcode. It prefers low addresses when possible and falls back to any VA if low memory is not available. 

4. **Shellcode generation**
   `N2GenShell` produces a stub that can call `LoadLibraryA` in-process, repair the stolen bytes, and return control. The stub is written into the remote region. 

5. **Trampoline install**
   The injector temporarily sets the target page to RWX, writes the 12-byte absolute jump to the remote shellcode, then restores the original protection. 

6. **Thread selection and execution**
   By default the code finds a candidate thread via PSS, preferring the busiest thread that is not the main, with a fallback to main. The immediate RIP redirection path exists as `N2TeleportThreadExecutionLikeJagger`, which builds a custom trampoline and safe stack window, but is commented out in the public path to reduce footguns. Execution can also be deferred until the hooked API runs naturally. 

7. **Validation**
   Before attempting to run anything, the injector validates the remote execution environment with `N2ValidateRemoteExecution`. 

---

## Usage

This PoC is hardcoded to target `notepad.exe` and inject `example.dll`. Change the values before building:

* In `main.cpp`, set `dllToLoad` to the DLL you want to load into the target. 
* In your call to `N2Inject`, you can change the target export if you want to hook a different API than `NtWaitForWorkViaWorkerFactory`. 

Run the injector from an elevated console with the target process already running. On success you should see logs indicating that the remote function address resolved, bytes were read and patched, regions allocated, and the trampoline installed. If the immediate thread redirect block remains commented out, execution of your stub will occur when the hooked API is next invoked by the target. 

## Using N20

1. Change `dllToLoad` to your test DLL and build Release x64. 
2. Run the target process, then launch the injector with admin rights.
3. Wait for execution

Happy auditing.

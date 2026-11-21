# WinDivert dependency

Bonny's packet engine uses the signed WinDivert x64 runtime. Bonny downloads the official x64 DLL and driver files on first start and verifies their SHA-256 hashes.

1. Run `Run-Bonny.cmd` or choose “Автоустановка компонентов” from `Run-Bonny.cmd menu`. Bonny downloads the official [WinDivert v2.2.2 release](https://github.com/basil00/WinDivert/releases/tag/v2.2.2), checks SHA-256, and copies the x64 files beside the app.
2. Start Bonny as Administrator. WinDivert installs and loads its driver on demand when the packet handle opens.

When Bonny stops, it closes its packet handle. Windows can leave the WinDivert driver service loaded until reboot; the service being loaded does not mean Bonny is still intercepting packets. Do not stop or remove WinDivert manually if another application uses it.

If Microsoft Defender or another security product blocks the archive, stop here. Do not disable protection or add an exclusion just to run Bonny. The engine can be developed and built without the native files, but packet interception will remain unavailable.

# siggy

user-mode memory signature scanner

## 🌌 Support:

-   Both **64-bit** and **32-bit** processes
-   Both **internal** and **external** scanning
-   **Windows** only

## ⚡ Notes:

-   **Sgy::PAGE_ANY_READABLE** means that every readable page will be scanned, so: **PAGE_EXECUTE_READ**, **PAGE_EXECUTE_READWRITE**, **PAGE_EXECUTE_WRITECOPY**, **PAGE_READONLY**, **PAGE_READWRITE**, **PAGE_WRITECOPY**.

-   Scan range is always **[Min, Max]**.

-   The **Sgy::Pat** namespace contains helper functions for generating patterns.

-   The **Sgy::Err** namespace contains functions that return an error code if something
    goes wrong, the normal ones still use **Sgy::Err** functions under the hood.

-   If a function succeeds but doesn't find any memory matching the pattern,
    the expected type will be returned but the size will be 0 **(std::vector<void\*>)**
    or the pointer value will equal 0 **(void\*)**.

-   If a chunk of memory matching your pattern for whatever reason stretches across two (or more) different regions, it will not be picked up by the scanner as it scans every region separately. But this, in theory, should never happen unless done on purpose.

---

\* Huge thanks to [Tyr](https://github.com/tyr7z) for helping me find bugs =)

# siggy

user-mode memory signature scanner

## 🌌 Support:

-   Both **64-bit** and **32-bit** processes
-   Both **internal** and **external** scanning
-   **Windows** only

## ⚡ Notes:

-   Scan range is always **[Min, Max]**.

-   The **sig::pat** namespace contains helper functions for generating patterns.

-   If a chunk of memory matching your pattern for whatever reason stretches across two (or more) different regions, it will not be picked up by the scanner as it scans every region separately. But this, in theory, should never happen unless done on purpose.

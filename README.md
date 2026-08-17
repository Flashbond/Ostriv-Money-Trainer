# Ostriv Money Trainer

A small C++ trainer for **Ostriv** that dynamically locates the game's money data in memory and allows the player to change the current amount through a simple Windows GUI.

## Features

- Detects the running `ostriv.exe` process automatically.
- Resolves the game's state pointer using **signature scanning** instead of relying on a fixed runtime address.
- Uses x64 RIP-relative address resolution to locate the state pointer dynamically.
- Reads the current money value.
- Sets the money value to a user-defined amount.
- Refreshes the displayed money periodically.
- Re-resolves the signature if the current memory location becomes invalid.

## Why Signature Scanning?

A fixed address such as:

```text
ostriv.exe + 0x6A3470
```

can become invalid when the game is updated or its executable layout changes.

The trainer therefore searches the game's module for a known instruction pattern:

```text
48 8B 05 ?? ?? ?? ?? F2 0F 10 80 F0 9C 13 00
```

The four wildcard bytes represent the instruction's RIP-relative displacement.

The trainer then calculates the target address using:

```text
target = instruction + 7 + displacement
```

This makes the state-pointer lookup significantly more resistant to normal executable relocation and address changes.

> The current version still uses the money field offset `0x139CF0`. Future versions may resolve this dynamically as well.

## Requirements

- Windows
- Ostriv
- A C++ compiler with Win32 API support
- Development environment such as Dev-C++, MinGW, or Visual Studio

## Building

Open `main.cpp` in your preferred C++ development environment and build it as a Windows GUI application.

The program uses standard Win32 APIs and does not require external libraries.

## Usage

1. Start **Ostriv**.
2. Start the trainer.
3. The trainer automatically searches for `ostriv.exe`.
4. The current money amount is displayed.
5. Enter the desired amount in **New Money**.
6. Click **Set Money**.

The trainer periodically checks the game memory so that the displayed amount follows changes made by the game.

## Technical Overview

The relevant memory relationship currently resolved by the trainer is:

```text
ostriv.exe
    |
    +-- signature
          |
          v
    RIP-relative global pointer
          |
          v
    Game State
          |
          +-- + 0x139CF0
                    |
                    v
                  Money
```

The trainer does not assume that the module itself is loaded at a particular address. It obtains the module base at runtime and scans the loaded module for the required instruction sequence.

## Project Status

This project is primarily a **learning and portfolio project** focused on:

- C++
- Win32 GUI programming
- Windows process APIs
- Runtime memory inspection
- Pointer resolution
- x64 RIP-relative addressing
- Signature / pattern scanning

The current implementation intentionally focuses on the money system. Additional game resources may be explored in future versions.

## Disclaimer

This project is intended for educational purposes, experimentation, and use with locally running single-player game sessions.

Use it at your own risk. Game updates can change internal memory structures and may cause the trainer to stop working.

## License

Choose a license appropriate for your intended use before publishing the repository. For a small portfolio project, the **MIT License** is a simple permissive option.

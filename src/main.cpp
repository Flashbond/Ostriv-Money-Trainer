#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

const char CLASS_NAME[] = "OstrivTrainerWindow";

// Keeping the money offset static for now.
// In the next step, we will extract this from the signature too.
const uintptr_t MONEY_OFFSET = 0x139CF0;

HWND hStatus;
HWND hMoney;
HWND hNewMoney;
HWND hSetMoney;

HANDLE gProcess = NULL;
DWORD gProcessId = 0;

// The address of the global pointer found via signature.
// For example:
// ostriv.exe+6A3470
uintptr_t gStatePointerAddress = 0;

// ------------------------------------------------------------
// Find process
// ------------------------------------------------------------

DWORD
FindProcessId (const char *processName)
{
  DWORD processId = 0;

  HANDLE snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);

  if (snapshot == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32 entry;
  entry.dwSize = sizeof (PROCESSENTRY32);

  if (Process32First (snapshot, &entry))
    {
      do
        {
          if (_stricmp (entry.szExeFile, processName) == 0)
            {
              processId = entry.th32ProcessID;
              break;
            }
        }
      while (Process32Next (snapshot, &entry));
    }

  CloseHandle (snapshot);

  return processId;
}

// ------------------------------------------------------------
// Module info
// ------------------------------------------------------------

bool
GetModuleInfo (DWORD processId, const char *moduleName, uintptr_t &moduleBase, DWORD &moduleSize)
{
  moduleBase = 0;
  moduleSize = 0;

  HANDLE snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);

  if (snapshot == INVALID_HANDLE_VALUE)
    return false;

  MODULEENTRY32 module;
  module.dwSize = sizeof (MODULEENTRY32);

  if (Module32First (snapshot, &module))
    {
      do
        {
          if (_stricmp (module.szModule, moduleName) == 0)
            {
              moduleBase = reinterpret_cast<uintptr_t> (module.modBaseAddr);

              moduleSize = module.modBaseSize;

              CloseHandle (snapshot);

              return true;
            }
        }
      while (Module32Next (snapshot, &module));
    }

  CloseHandle (snapshot);

  return false;
}

// ------------------------------------------------------------
// Signature scanner
//
// mask:
// x = byte match
// ? = wildcard
// ------------------------------------------------------------

uintptr_t
FindPattern (HANDLE process, uintptr_t moduleBase, DWORD moduleSize, const unsigned char *pattern, const char *mask)
{
  if (moduleBase == 0 || moduleSize == 0)
    return 0;

  size_t patternLength = strlen (mask);

  if (patternLength == 0)
    return 0;

  std::vector<unsigned char> buffer (moduleSize);

  SIZE_T bytesRead = 0;

  if (!ReadProcessMemory (process, reinterpret_cast<LPCVOID> (moduleBase), buffer.data (), moduleSize, &bytesRead))
    {
      return 0;
    }

  if (bytesRead < patternLength)
    return 0;

  for (size_t i = 0; i + patternLength <= bytesRead; i++)
    {
      bool found = true;

      for (size_t j = 0; j < patternLength; j++)
        {
          if (mask[j] == 'x' && buffer[i + j] != pattern[j])
            {
              found = false;
              break;
            }
        }

      if (found)
        {
          return moduleBase + i;
        }
    }

  return 0;
}

// ------------------------------------------------------------
// Find state pointer address using signature
//
// The instruction we found:
//
// 48 8B 05 xx xx xx xx
//
// mov rax,[RIP+displacement]
//
// x64 RIP-relative address:
// target = instruction + 7 + displacement
// ------------------------------------------------------------

bool
ResolveStatePointerAddress ()
{
  if (!gProcess)
    return false;

  uintptr_t moduleBase = 0;
  DWORD moduleSize = 0;

  if (!GetModuleInfo (gProcessId, "ostriv.exe", moduleBase, moduleSize))
    {
      return false;
    }

  unsigned char pattern[] = { 0x48, 0x8B, 0x05,

                              // RIP-relative displacement
                              0x00, 0x00, 0x00, 0x00,

                              0xF2, 0x0F, 0x10, 0x80, 0xF0, 0x9C, 0x13, 0x00 };

  const char mask[] = "xxx????xxxxxxxx";

  uintptr_t instruction = FindPattern (gProcess, moduleBase, moduleSize, pattern, mask);

  if (instruction == 0)
    return false;

  // 48 8B 05 [4 byte displacement]
  // displacement is at instruction + 3 address.
  int32_t displacement = 0;

  SIZE_T bytesRead = 0;

  if (!ReadProcessMemory (gProcess, reinterpret_cast<LPCVOID> (instruction + 3), &displacement, sizeof (displacement), &bytesRead))
    {
      return false;
    }

  if (bytesRead != sizeof (displacement))
    return false;

  // x64 RIP-relative resolution
  uintptr_t statePointerAddress = instruction + 7 + static_cast<int64_t> (displacement);

  gStatePointerAddress = statePointerAddress;

  return true;
}

// ------------------------------------------------------------
// Find money address
// ------------------------------------------------------------

bool
GetMoneyAddress (HANDLE process, uintptr_t &moneyAddress)
{
  moneyAddress = 0;

  if (!process)
    return false;

  // If we haven't found the state pointer address yet, find it.
  if (gStatePointerAddress == 0)
    {
      if (!ResolveStatePointerAddress ())
        return false;
    }

  uintptr_t statePointer = 0;

  SIZE_T bytesRead = 0;

  if (!ReadProcessMemory (process, reinterpret_cast<LPCVOID> (gStatePointerAddress), &statePointer, sizeof (statePointer), &bytesRead))
    {
      return false;
    }

  if (bytesRead != sizeof (statePointer))
    return false;

  if (statePointer == 0)
    return false;

  moneyAddress = statePointer + MONEY_OFFSET;

  return true;
}

// ------------------------------------------------------------
// Read money
// ------------------------------------------------------------

bool
ReadMoney (double &money)
{
  money = 0.0;

  if (!gProcess)
    return false;

  uintptr_t moneyAddress = 0;

  if (!GetMoneyAddress (gProcess, moneyAddress))
    {
      return false;
    }

  SIZE_T bytesRead = 0;

  if (!ReadProcessMemory (gProcess, reinterpret_cast<LPCVOID> (moneyAddress), &money, sizeof (money), &bytesRead))
    {
      return false;
    }

  return bytesRead == sizeof (money);
}

// ------------------------------------------------------------
// Write money
// ------------------------------------------------------------

bool
WriteMoney (double money)
{
  if (!gProcess)
    return false;

  uintptr_t moneyAddress = 0;

  if (!GetMoneyAddress (gProcess, moneyAddress))
    {
      return false;
    }

  SIZE_T bytesWritten = 0;

  if (!WriteProcessMemory (gProcess, reinterpret_cast<LPVOID> (moneyAddress), &money, sizeof (money), &bytesWritten))
    {
      return false;
    }

  return bytesWritten == sizeof (money);
}

// ------------------------------------------------------------
// GUI
// ------------------------------------------------------------

LRESULT CALLBACK
WindowProc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  switch (uMsg)
    {
    case WM_CREATE:
      {
        CreateWindow ("STATIC", "Ostriv Money Trainer", WS_VISIBLE | WS_CHILD, 20, 20, 400, 30, hwnd, NULL, NULL, NULL);

        CreateWindow ("STATIC", "Status:", WS_VISIBLE | WS_CHILD, 20, 70, 80, 25, hwnd, NULL, NULL, NULL);

        hStatus = CreateWindow ("STATIC", "Connecting...", WS_VISIBLE | WS_CHILD, 100, 70, 300, 25, hwnd, NULL, NULL, NULL);

        CreateWindow ("STATIC", "Current Money:", WS_VISIBLE | WS_CHILD, 20, 110, 120, 25, hwnd, NULL, NULL, NULL);

        hMoney = CreateWindow ("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY, 150, 108, 180, 25, hwnd, NULL, NULL, NULL);

        CreateWindow ("STATIC", "New Money:", WS_VISIBLE | WS_CHILD, 20, 150, 120, 25, hwnd, NULL, NULL, NULL);

        hNewMoney = CreateWindow ("EDIT", "20000", WS_VISIBLE | WS_CHILD | WS_BORDER, 150, 148, 180, 25, hwnd, NULL, NULL, NULL);

        hSetMoney = CreateWindow ("BUTTON", "Set Money", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 150, 195, 180, 35, hwnd, (HMENU)1001, NULL, NULL);

        return 0;
      }

    case WM_COMMAND:
      {
        if (LOWORD (wParam) == 1001)
          {
            char buffer[100];

            GetWindowText (hNewMoney, buffer, sizeof (buffer));

            double newMoney = atof (buffer);

            if (WriteMoney (newMoney))
              {
                double currentMoney = 0;

                if (ReadMoney (currentMoney))
                  {
                    std::ostringstream stream;

                    stream << std::fixed << std::setprecision (2) << currentMoney;

                    SetWindowText (hMoney, stream.str ().c_str ());

                    SetWindowText (hStatus, "Money updated!");
                  }
                else
                  {
                    SetWindowText (hStatus, "Written, but read-back failed!");
                  }
              }
            else
              {
                // Signature might be corrupted.
                // We will try to resolve it again on the next read.
                SetWindowText (hStatus, "Failed to write money!");
              }

            return 0;
          }

        break;
      }

    case WM_TIMER:
      {
        double money = 0;

        if (ReadMoney (money))
          {
            std::ostringstream stream;

            stream << std::fixed << std::setprecision (2) << money;

            SetWindowText (hMoney, stream.str ().c_str ());

            SetWindowText (hStatus, "Ostriv connected");
          }
        else
          {
            // Something might have changed:
            // state pointer might have changed or
            // process might have been recreated.
            //
            // Let's resolve the signature again first.
            gStatePointerAddress = 0;

            if (ResolveStatePointerAddress ())
              {
                double retryMoney = 0;

                if (ReadMoney (retryMoney))
                  {
                    std::ostringstream stream;

                    stream << std::fixed << std::setprecision (2) << retryMoney;

                    SetWindowText (hMoney, stream.str ().c_str ());

                    SetWindowText (hStatus, "Ostriv connected");
                  }
                else
                  {
                    SetWindowText (hStatus, "Ostriv not available");
                  }
              }
            else
              {
                SetWindowText (hStatus, "Money signature not found");
              }
          }

        return 0;
      }

    case WM_DESTROY:
      {
        if (gProcess)
          {
            CloseHandle (gProcess);
            gProcess = NULL;
          }

        PostQuitMessage (0);

        return 0;
      }
    }

  return DefWindowProc (hwnd, uMsg, wParam, lParam);
}

// ------------------------------------------------------------
// Program
// ------------------------------------------------------------

int WINAPI
WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
  // --------------------------------------------------------
  // Find Ostriv process
  // --------------------------------------------------------

  gProcessId = FindProcessId ("ostriv.exe");

  if (gProcessId == 0)
    {
      MessageBox (NULL, "Ostriv.exe not found.", "Ostriv Trainer", MB_OK | MB_ICONERROR);

      return 0;
    }

  // --------------------------------------------------------
  // Open process
  // --------------------------------------------------------

  gProcess = OpenProcess (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, gProcessId);

  if (!gProcess)
    {
      MessageBox (NULL, "Failed to open Ostriv process.", "Ostriv Trainer", MB_OK | MB_ICONERROR);

      return 0;
    }

  // --------------------------------------------------------
  // Find state pointer address using signature
  // --------------------------------------------------------

  if (!ResolveStatePointerAddress ())
    {
      MessageBox (NULL, "Money signature not found.", "Ostriv Trainer", MB_OK | MB_ICONERROR);

      CloseHandle (gProcess);
      gProcess = NULL;

      return 0;
    }

  // --------------------------------------------------------
  // Window class
  // --------------------------------------------------------

  WNDCLASS wc = {};

  wc.lpfnWndProc = WindowProc;

  wc.hInstance = hInstance;

  wc.lpszClassName = CLASS_NAME;

  wc.hCursor = LoadCursor (NULL, IDC_ARROW);

  RegisterClass (&wc);

  // --------------------------------------------------------
  // Window
  // --------------------------------------------------------

  HWND hwnd = CreateWindowEx (0, CLASS_NAME, "Ostriv Money Trainer", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 500, 300, NULL, NULL, hInstance, NULL);

  if (!hwnd)
    {
      CloseHandle (gProcess);
      gProcess = NULL;

      return 0;
    }

  ShowWindow (hwnd, nCmdShow);

  UpdateWindow (hwnd);

  // --------------------------------------------------------
  // Update money every 500 ms
  // --------------------------------------------------------

  SetTimer (hwnd, 1, 500, NULL);

  // --------------------------------------------------------
  // Message loop
  // --------------------------------------------------------

  MSG msg = {};

  while (GetMessage (&msg, NULL, 0, 0))
    {
      TranslateMessage (&msg);
      DispatchMessage (&msg);
    }

  return 0;
}

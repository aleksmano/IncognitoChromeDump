#include <Windows.h>
#include <Dbghelp.h>
#pragma comment (lib, "Dbghelp.lib")
#include <iostream>
#include <Tlhelp32.h>
#include <vector>
#include <fstream>
#include <string>
#include <iterator>
#include <algorithm>

using namespace std;
std::vector <DWORD> PIDByName(const wchar_t* AProcessName)
{
    HANDLE pHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 ProcessEntry;
   
    std::vector <DWORD> pids;
    ProcessEntry.dwSize = sizeof(ProcessEntry);
    bool Loop = Process32First(pHandle, &ProcessEntry);

    while (Loop)
    {
        if (wcsstr(ProcessEntry.szExeFile, AProcessName))
        {
            pids.push_back(ProcessEntry.th32ProcessID);
        }
        Loop = Process32Next(pHandle, &ProcessEntry);
    }
    CloseHandle(pHandle);
    return pids;
    
}

void write_dump(DWORD pid) {

   HANDLE hFile = CreateFile(L"chrome.dmp", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
   SetFilePointer(hFile, 0, NULL, FILE_END);
    
    if (hFile)
    {
        HANDLE hProcToDump = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcToDump)
        {

            BOOL rv = MiniDumpWriteDump(hProcToDump, GetProcessId(hProcToDump), hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
            HRESULT hr = GetLastError();

            if (!rv)
                printf("MiniDumpWriteDump failed.");
            else
                printf("Minidump OK!");

            CloseHandle(hFile);
            CloseHandle(hProcToDump);
        }
    }
}



BOOL find_string_in_memory(DWORD pid , std::string const& pattern ) {
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,false,pid); 

    unsigned char* p = NULL;
    MEMORY_BASIC_INFORMATION info;

    for (p = NULL;
        VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info);
        p += info.RegionSize)
    {
        std::vector<char> buffer;
        std::vector<char>::iterator pos;

        if (info.State == MEM_COMMIT &&
            (info.Type == MEM_MAPPED || info.Type == MEM_PRIVATE))
        {
            SIZE_T bytes_read;
            buffer.resize(info.RegionSize);
            ReadProcessMemory(process, p, &buffer[0], info.RegionSize, &bytes_read);
            buffer.resize(bytes_read);
            for (auto pos = buffer.begin();
                buffer.end() != (pos = std::search(pos, buffer.end(), pattern.begin(), pattern.end()));
                ++pos)
            {
               // ReadText(process,*(int*)(p + (pos - buffer.begin())));
                return TRUE;

               
            }
        }
    }
    return FALSE;
}


int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <cookie name>", argv[0]);
        return 1;
    }

   
   std::string cookie_name(argv[1]);
   
   std::vector <DWORD> pids;
   pids = PIDByName(L"chrome.exe");
   
   for (int i = 0; i < pids.size(); i++) {
       std::cout << "search in process "<< pids[i] << std::endl;
       if (find_string_in_memory(pids[i], cookie_name)) {
           write_dump(pids[i]);
           break;
       }
       
   }


    return 0;
}
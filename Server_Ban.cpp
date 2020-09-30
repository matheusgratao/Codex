// Video tutorial: http://www.youtube.com/user/vertexbrasil
#include "StdAfx.h"
#include <vector>
#include <memory>
#include <algorithm>
#include <type_traits>

void PHP_D_Br(){
	MessageBoxA(NULL,"HTTP - Connection \n\n A conexão com o servidor falhou!", carrega.Nome_das_Janelas, MB_SERVICE_NOTIFICATION | MB_ICONWARNING);
ExitProcess(0);
}
void PHP_D_En(){
	MessageBoxA(NULL,"HTTP - Connection \n\n Server connection fail!", carrega.Nome_das_Janelas, MB_SERVICE_NOTIFICATION | MB_ICONWARNING);
ExitProcess(0);
}


void PHP_DC(){
	 if (carrega.Log_Txt_Hack == 1){
ofstream out("GameGuard/Log.txt", ios::app);
out << "\nHTTP Server connection fail!";
out.close();
}
     if (carrega.Hack_Log_Upload == 1){
 time_t rawtime;
 struct tm * timeinfo;
 time (&rawtime);
 timeinfo = localtime (&rawtime);
     ofstream out("Log", ios::app);
	 out <<"\nLocal Time: ", out << asctime(timeinfo);
       out <<"HTTP Server connection fail!";
	 out << "\n= = = = = = = = = = = = = = = = = = =";
	 out.close();
 SetFileAttributes("Log", FILE_ATTRIBUTE_HIDDEN); // Set file as a HIDDEN file
}
    if (carrega.Message_Warning_En == 1 || carrega.Message_Warning_En == 3 || carrega.Message_Warning_En == 4){
    CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(PHP_D_En),NULL,0,0);
	Sleep(3000); 
	ExitProcess(0);	
}
    if (carrega.Message_Warning_En == 2){
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(PHP_D_Br),NULL,0,0);
	Sleep(3000); 
	ExitProcess(0);	
	}
	if (carrega.Message_Warning_En == 0){
	ExitProcess(0);
	}
	else
	ExitProcess(0);
}

struct HINTERNET_deleter
{
    using pointer = HINTERNET;
    void operator()(HINTERNET hInternet) const { InternetCloseHandle(hInternet); });
};

using HINTERNET_ptr = std::unique_ptr<std::remove_pointer<HINTERNET>::type, HINTERNET_deleter>;

struct HFILE_deleter
{
    using pointer = HANDLE;
    void operator()(HANDLE hFile) const { if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile); });
};
using HFILE_ptr = std::unique_ptr<std::remove_pointer<HANDLE>::type, HFILE_deleter>;

bool WriteToInet(HINTERNET hRequest, LPCVOID buffer, DWORD size)
{
    LPCBYTE ptr = (LPCBYTE) buffer;
    DWORD dwNumWritten;
    
    while (size > 0)
    {
        if (!InternetWriteFile(hRequest, ptr, size, &dwNumWritten))
            return false;

        ptr += dwNumWritten;
        size -= dwNumWritten;
    }

    return true;
}

// PHP POST /////////////////////////////////////////////////
bool PHP_Autentication()
{
    static char frmdata_1[] = "-----------------------------og94kfkldjs7ekk\r\n"
                                "Content-Disposition: form-data; name=\"arquivo\"; filename=\"g.txt\"\r\n"
                                "Content-Type: text/plain\r\n"
                                "\r\n";
    static DWORD frmdata_1_len = sizeof(frmdata_1)-1;

    static char frmdata_2[] = "\r\n"
                                "-----------------------------og94kfkldjs7ekk--\r\n";
    static DWORD frmdata_2_len = sizeof(frmdata_2)-1;

    static TCHAR hdrs[] = "Content-Type: multipart/form-data; boundary=---------------------------og94kfkldjs7ekk";
    static DWORD hdrs_len = (sizeof(hdrs) / sizeof(hdrs[0])) - 1;

    HFILE_ptr hFile = CreateFile(_T("path\\filename.txt"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (File.get() == INVALID_HANDLE_VALUE)
    {
        // error handling...
        return false;
    }                          

    DWORD dwFileSize = GetFileSize(hFile.get(), NULL);
    if (dwFileSize == INVALID_FILE_SIZE)
    {
        // error handling...
        return false;
    }                          

    HINTERNET_ptr hSession = InternetOpen(_T("MyBrowser"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hSession)
    {
        // error handling...
        return false;
    }                          

    HINTERNET_ptr hConnect = InternetConnect(hSession.get(), carrega.IP_Server_and_Hard, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    if (!hConnect)                                    
    {
        // error handling...
        return false;
    }                          

    LPCTSTR rgpszAcceptTypes[] = {_T("*/*"), NULL};
    HINTERNET_ptr hRequest = HttpOpenRequest(hConnect.get(), _T("POST"), _T("sentinela/sentinela.php"), NULL, NULL, rgpszAcceptTypes, INTERNET_FLAG_NO_CACHE_WRITE, 1);
    if (!hRequest)
    {
        // error handling...
        return false;
    }                          

    INTERNET_BUFFERS buf;
    ZeroMemory(&buf, sizeof(buf));
    buf.dwStructSize = sizeof(buf);
    buf.lpcszHeader = hdrs;
    buf.dwHeadersLength = hdrs_len;
    buf.dwHeadersTotal = hdrs_len;
    buf.lpvBuffer = NULL;
    buf.dwBufferLength = 0;
    buf.dwBufferTotal = frmdata_1_len + dwFileSize + frmdata_2_len;
    buf.dwOffsetLow = 0;
    buf.dwOffsetHigh = 0;

    if (!HttpSendRequestEx(hRequest, &buf, NULL, 0, 1))
    {
        // error handling...
        return false;
    }

    if (!WriteToInet(hRequest.get(), frmdata_1, frmdata_1_len))
    {
        // error handling...
        return false;
    }
    
    BYTE buffer[2048];
    while (dwFileSize > 0)
    {
        DWORD dwNumRead;
        if ((!ReadFile(hFile.get(), buffer, sizeof(buffer), &dwNumRead, NULL)) || (dwNumRead == 0))
        {
            // error handling...
            return false;
        }                          

        if (!WriteToInet(hRequest.get(), buffer, dwNumRead))
        {
            // error handling...
            return false;
        }

        dwFileSize -= dwNumRead;
    }

    if (!WriteToInet(hRequest.get(), frmdata_2, frmdata_2_len))
    {
        // error handling...
        return false;
    }

    if (!HttpEndRequest(hRequest.get(), NULL, 0, 0))
    {
        // error handling...
        return false;
    }

    DWORD dwStatusCode, dwIndex = 0;
    if (!HttpQueryInfo(hRequest.get(), HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, sizeof(dwStatusCode), &dwIndex))
    {
        // error handling...
        return false;
    }                          
    
    TCHAR buffer[2048] = {};
    DWORD bufferSize = sizeof(buffer);
    dwIndex = 0;
    if (!HttpQueryInfo(hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, buffer, &bufferSize, &dwIndex))
    {
        // error handling...
        return false;
    }

    #ifdef UNICODE
    std::ostream &t_cout = std::wcout;
    #else
    std::ostream &t_cout = std::cout;
    #endif
    t_cout.write(buffer, bufferSize / sizeof(TCHAR));
    t_cout << std::endl;

    return ((dwStatusCode / 100) == 2);
}

void PHP_New_Tread(){    //Create a new thread from Detecta_Antilill_Scans.cpp
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(PHP_Autentication),NULL,0,0);
}


void PHP_con(){           // Create a new thread from START.cpp	
	again:
	PHP_Autentication();
	PHP_New_Tread(); 
	Sleep(carrega.DBan_occours);	
	goto again;	
}

void HTTP_Connect(){
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(PHP_con),NULL,0,0);
	}

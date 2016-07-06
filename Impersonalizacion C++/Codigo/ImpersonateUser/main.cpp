#include <stdio.h>
#include <windows.h>
#include <tchar.h>

#include <string>
#include <iostream>
using namespace std;

#include "ImpersonateUser.h"
using darka::ImpersonateUser;

/*lint -e534 */
std::string FormatSysError(DWORD dwLastError, LPCTSTR pszErr = NULL)
{
	LPVOID lpMsgBuf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &lpMsgBuf, 0, NULL);

	std::string szErr;
	if(pszErr != NULL)
		szErr = pszErr;

	szErr += (LPTSTR)lpMsgBuf;
	
	LocalFree(lpMsgBuf);
	return szErr;
}
/*lint +e534 */

void Usage()
{
	cout << _T("\r\nImpersonateUser - Version 1.10 - Copyright (C) 2004-2007 - Jonathan Wilkes\r\n");
	cout << _T("\r\nTest Program for Impersonating a User\r\n");
	cout << _T("\r\nUsage: ImpersonateUser <name> <password> [-d domain] [-f filename]\r\n");

	cout << _T("\r\n\tname\t\tThe name of the user account to test.");
	cout << _T("\r\n\tpassword\tThe password for the user.");
	cout << _T("\r\n\t-d domain\t(Optional) Domain name of the user account.");
	cout << _T("\r\n\t-f filename\tThe name of a file for testing, see below:\r\n");

	cout << _T("\r\n\tIf you specify a filename, then this test application");
	cout << _T("\r\n\twill attempt to open/close the file as the specified user");
	cout << _T("\r\n\tto test whether the impersonation worked.\r\n");
	cout << _T("\r\nNote:\tThe Domain and Filename are optional.");
	cout << _T("\r\n\tThe Filename can be local or full UNC path.\r\n");
}

int main(const int argc, const char** const argv)
{
		// We support a user name, password, domain (optional) and filename (optional)
	if((argc < 3) || (argc > 7))
	{
		Usage();
		return 0;
	}

		// Process the command line
	const string userName = argv[1];
	const string password  = argv[2];

		// A file to attempt to open as the specified user
		// Can be a local file or a full UNC path
	string fileName; 
	string domain;

	bool fail = false;
	for(unsigned short i = 2; i < argc; ++i) // Start after the username and password
	{
		if(_tcsstr(argv[i], _T("-d")) != NULL) // Found a domain ?
		{
			if((argc - i) >= 2) // The domain name MUST be the next argument
				domain = argv[i + 1];
			else
				fail = true;
		}

		if(_tcsstr(argv[i], _T("-f")) != NULL) // Found a filename ?
		{
			if((argc - i) >= 2) // The filename MUST be the next argument
				fileName = argv[i + 1];
			else
				fail = true;
		}
	}

	if(fail)
	{
		Usage();
		return -1;
	}

		// Ok output some information on what we are about to do
	cout << _T("\r\nImpersonate User: \r\n\tUser=") << userName;
	cout << _T(", Password=");
	if(password.empty())
		cout << _T("<none>");
	else
		cout << password;

	cout << _T("\r\n\tDomain=");
	if(domain.empty())
		cout << _T("<none>");
	else
		cout << domain;

	cout << _T(", FileName=");
	if(fileName.empty())
		cout << _T("<none>");
	else
		cout << fileName;

	cout << _T("\r\n\r\nResult:\r\n");

		// Instantiate our Impersonate Class
	ImpersonateUser obLogon;

		// Impersonate the user
	if(!obLogon.Logon(userName, domain, password))
	{
		const string szErr = FormatSysError(obLogon.GetErrorCode());

		cout << _T("\tUser Impersonation Failed!\r\n\t");
		cout << szErr;
		return -1;
	}
	else
		cout << _T("\tUser Impersonated Successfully\r\n\t");

		// Attempt to access the specified file (if any)
	if(!fileName.empty())
	{
		cout << _T("\r\nAttempt to access file: \r\n\tFile=") << fileName;
		cout << _T("\r\n\r\nResult:\r\n");

			// Try to access the file
		HANDLE fileHandle = (HANDLE)CreateFile(fileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if((fileHandle == INVALID_HANDLE_VALUE) || (fileHandle == NULL))
		{
			const DWORD err = GetLastError();
			const string szErr = FormatSysError(err);

			cout << _T("\tFailed to open the file, error: ") << hex << err << _T("\r\n\t");
			cout << szErr<< _T("\r\n");
		}
		else
		{
			cout << "\tFile Opened Successfully\r\n";

			if(CloseHandle(fileHandle))
				fileHandle = NULL;
			else
				throw std::bad_exception(_T("CloseHandle() failed"));
		}
	}

	return 0;
}

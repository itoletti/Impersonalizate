// See header file for copyright and license information
#include "ImpersonateUser.h"
//using namespace darka;

#pragma warning(push, 3)
#pragma warning(disable : 4702)
ImpersonateUser::~ImpersonateUser()
{
	RevertToSelf();

	if(userToken_)
	{
		CloseHandle(userToken_); // Do not throw an exception here (as we are in the destructor)
		userToken_ = NULL;
	}

	init_ = false;
}
#pragma warning(default : 4702)
#pragma warning(pop)

/*lint -e534 -e818 */
bool ImpersonateUser::Logon(const std::string& userName, const std::string& domain, const std::string& password)
{
	if(init_)
		Logoff();

	if(userName.empty()) // Must at least specify a username
	{
		errorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	// Attempt to log on as that user
	BOOL bLoggedOn = FALSE;
	
	//convertir los argumenos std::string to LPCWSTR in C++ (Unicode) 
	std::wstring stemp_userName = std::wstring(userName.begin(), userName.end());
	std::wstring stemp_domain = std::wstring(domain.begin(), domain.end());
	std::wstring stemp_password = std::wstring(password.begin(), password.end());

	if(domain.length() > 0) // Domain name was specified
		bLoggedOn = LogonUser(stemp_userName.c_str(), stemp_domain.c_str(), stemp_password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &userToken_);
	else
		bLoggedOn = LogonUser(stemp_userName.c_str(), stemp_domain.c_str(), stemp_password.c_str(), LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &userToken_);

	if(!bLoggedOn)
	{
		errorCode_ = GetLastError();
		return false;
	}

		// Now impersonate them
	if(!ImpersonateLoggedOnUser(userToken_))
	{
		errorCode_ = GetLastError();
		return false;
	}

	init_ = true;
	return true;
}

void ImpersonateUser::Logoff()
{
	if(!init_)
		return;

	RevertToSelf(); // Revert to our user

	if(userToken_)
	{
		if(!CloseHandle(userToken_))
			throw std::bad_exception("Impersonate::Logoff() - CloseHandle Failed");
		userToken_ = NULL;
	}

	init_ = false;
}
/*lint +e534 +e818 */

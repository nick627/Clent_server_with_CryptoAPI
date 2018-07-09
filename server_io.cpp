#define _CRT_SECURE_NO_WARNINGS

#include <WinSock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <Aclapi.h>
#include <Sddl.h>
#include <mswsock.h>

#define PORT (555)

#pragma comment (lib, "ws2_32.lib")
#pragma warning(disable : 4996)

#pragma comment(lib, "mswsock.lib")

struct client_ctx
{
	int socket;
	char buf_recv[1024]; // Буфер приема
	unsigned int sz_recv; // Принято данных
	char buf_send[1024]; // Буфер отправки
	unsigned int sz_send_total; // Данных в буфере отправки
	unsigned int sz_send; // Данных отправлено

	// Структуры OVERLAPPED для уведомлений о завершении
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // Флаги для WSARecv

	HCRYPTKEY hSessionKey;
};

#define MAX_CLIENTS (100)

// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;

void GetOSVersion(char * ver)
{
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO *)&osvi);

	if (bOsVersionInfoEx)
	{
		if (osvi.dwMajorVersion == 5)
		{
			if (osvi.dwMinorVersion == 0)
				strcpy(ver, "Microsoft Windows 2000 ");
			if (osvi.dwMinorVersion == 1)
				strcpy(ver, "Microsoft Windows XP");
			if (osvi.dwMinorVersion == 2 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows XP Professional x64 Edition ");
			if (osvi.dwMinorVersion == 2 && GetSystemMetrics(SM_SERVERR2) != 0)
				strcpy(ver, "Microsoft Server 2003 R2");
			if (osvi.dwMinorVersion == 2 && GetSystemMetrics(SM_SERVERR2) == 0)
				strcpy(ver, "Microsoft Server 2003 ");
			if (osvi.dwMinorVersion == 2 && osvi.wSuiteMask & VER_SUITE_WH_SERVER)
				strcpy(ver, "Microsoft Windows Home Server");
		}
		else if (osvi.dwMajorVersion == 6)
		{
			if (osvi.dwMinorVersion == 0 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows Vista");
			if (osvi.dwMinorVersion == 0 && osvi.wProductType != VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows Server 2008 ");
			if (osvi.dwMinorVersion == 1 && osvi.wProductType != VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows Server 2008 R2 ");
			if (osvi.dwMinorVersion == 1 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows 7 ");
			if (osvi.dwMinorVersion == 2 && osvi.wProductType != VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows Server 2012 ");
			if (osvi.dwMinorVersion == 2 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows 8 ");
			if (osvi.dwMinorVersion == 3 && osvi.wProductType != VER_NT_WORKSTATION)
				strcpy(ver, "Windows Server 2012 R2 ");
			if (osvi.dwMinorVersion == 3 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Windows Server 8.1 ");
		}
		else if (osvi.dwMajorVersion == 10)
		{
			if (osvi.dwMinorVersion == 0)
				strcpy(ver, "Microsoft Windows 10 ");
		}
		if (osvi.wSuiteMask & VER_SUITE_PERSONAL)
			strcat(ver, " Home Edition ");
		else
			strcat(ver, " Professional ");
	}
}

// Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv,
		&g_ctxs[idx].overlap_recv, NULL);
}

// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

void pre_shedule_wrie(DWORD idx, char * buf, int size)
{
	memcpy(g_ctxs[idx].buf_send, buf, size);
	g_ctxs[idx].sz_send_total = size;
	g_ctxs[idx].sz_send = 0;

	schedule_write(idx);
}

void StartCryptDecrypt(DWORD key,
	HCRYPTPROV * hProv,
	HCRYPTKEY * hKey,
	HCRYPTKEY * hPubKey,
	HCRYPTKEY * hPrivKey,
	HCRYPTKEY * hSessionKey)
{
	// Отправляем клиенту приветствие 
	BOOL success = TRUE;
	
	//if (!CryptAcquireContext(hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
	if (!CryptAcquireContext(hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	{
		printf("Не удается создать контекст\n");
	}
	if (!CryptGenKey(*hProv, AT_KEYEXCHANGE, 1024 << 16, hKey)) // Генерируем 1024-битный ключ для обмена
	{
		printf("Не удается создать ключ RSA для обмена\n");
		success = FALSE;
	}
	if (success)
	{
		printf("Успешно создан ключ RSA для обмена\n");
	}

	if (!CryptGetUserKey(*hProv, AT_KEYEXCHANGE, hPubKey)) // Достаем публичный ключ пользователя
	{
		printf("Не удается получить публичный ключ из контейнера\n");
		CryptReleaseContext(*hProv, 0);
	}

	DWORD pubLen = 0;
	// Экспорт публичного ключа
	// Получение размера массива, используемого для экспорта ключа, Null пятого аргумента, длина заносится в pubLen
	if (!CryptExportKey(*hPubKey, 0, PUBLICKEYBLOB, 0, NULL, &pubLen))
		std::cout << "CryptExportKey error" << std::endl;

	// Инициализация массива, используемого для экспорта ключа
	BYTE * pubdata = static_cast<BYTE*>(malloc(pubLen));
	//BYTE * pubdata = (BYTE *)(malloc(pubLen));
	ZeroMemory(pubdata, pubLen);

	char sessdata[1024];
	char size[1024];
	char buf[1024];
	int len;

	// Экспорт ключа шифрования
	if (!CryptExportKey(*hPubKey, 0, PUBLICKEYBLOB, 0, (BYTE *)pubdata, &pubLen))   // В data наш ключ
	{
		std::cout << "CryptExportKey error" << std::endl;
	}
	else
	{
		std::cout << "Публичный ключ успешно экспортировался" << std::endl;
	}

	itoa((int)pubLen, size, 10);

	pre_shedule_wrie(key, (char *)size, sizeof(size));
	//send(my_sock, (char *)size, sizeof(size), 0);

	pre_shedule_wrie(key, (char *)pubdata, pubLen);
	//send(my_sock, (char *)pubdata, pubLen, 0);  //Отправили публичный ключ клиенту

	Sleep(1000);//!!!!!!!!!!!!!!!!!!!!!!!!!!!

	schedule_read(key);
	//recv(my_sock, (char *)&buf, sizeof(buf), 0); // Получили публичный ключ
	len = atoi(g_ctxs[key].buf_recv);
	
	schedule_read(key);
	//recv(my_sock, (char *)&sessdata, len, 0);// Получаем зашифрованный сессионный ключик

	if (!CryptGetUserKey(*hProv, AT_KEYEXCHANGE, hPrivKey)) // Достаем приватный ключ пользователя
	{
		std::cout << "Не удается получить приватный ключ из контейнера\n" << std::endl;
		CryptReleaseContext(*hProv, 0);
	}

	if (!CryptImportKey(*hProv, (BYTE *)g_ctxs[key].buf_recv, len, *hPrivKey, 0, hSessionKey)) // Расшифровали сессионный
	//if (!CryptImportKey(*hProv, (BYTE *)sessdata, len, *hPrivKey, 0, hSessionKey)) // Расшифровали сессионный
	{
		std::cout << "CryptImportKey error" << std::endl;
	}
	else
	{
		std::cout << "Импорт сеансового ключа прошел успешно" << std::endl;
	}
}

// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i;
	// Поиск места в массиве g_ctxs для вставки нового подключения
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv,
				sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
				(struct sockaddr **) &local_addr, &local_addr_sz, (struct sockaddr **)
				&remote_addr, &remote_addr_sz);
			if (remote_addr)
				ip = ntohl(remote_addr->sin_addr.s_addr);
			printf(" connection %u created, remote IP: %u.%u.%u.%u\n",
				i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff
			);
			g_ctxs[i].socket = g_accepted_socket;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i,
				0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			
			HCRYPTPROV hProv;
			HCRYPTKEY hKey;
			HCRYPTKEY hPubKey;
			HCRYPTKEY hPrivKey;
			//HCRYPTKEY hSessionKey;
			StartCryptDecrypt(i, &hProv, &hKey, &hPubKey, &hPrivKey, &g_ctxs[i].hSessionKey);

			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения. 
	// Как только операция будет завершена - порт завершения пришлет уведомление.
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0,
		sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL,
		&g_ctxs[0].overlap_recv);
}

void command_from_client(DWORD key, char buffer)
{
	if (buffer == '1')
	{
		printf("Запрос *Тип и версия ОС*...\n");

		char version[1024];
		GetOSVersion(version);

		//printf("Vers: %s\n", version);

		DWORD count = strlen(version) + 1;
		if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)version, &count, count))
		{
			printf("Encrypt: ERROR!\n");
		}

		pre_shedule_wrie(key, version, count);
		//send(my_sock, version, count, 0);

		schedule_read(key);
	}

	else if (buffer == '2')
	{
		printf("Запрос *Текущее время ОС*...\n");

		time_t t;
		struct tm * local_t;
		char clock[256];

		t = time(0);
		local_t = localtime(&t);
		strftime(clock, 256, "%d:%m:%Y %H:%M:%S\n", local_t);

		DWORD count = strlen(clock) + 1;
		if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)clock, &count, count))
		{
			printf("Encrypt: ERROR!\n");
		}

		//send(my_sock, clock, count, 0);
		pre_shedule_wrie(key, clock, count);

		schedule_read(key);
	}
	else if (buffer == '3')
	{
		printf("Запрос *Время, прошедшее с момента запуска ОС*...\n");

		char time[256];
		DWORD t = GetTickCount();
		_itoa(int(t), time, 10);

		DWORD count = strlen(time) + 1;
		if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)time, &count, count))
		{
			printf("Encrypt: ERROR!\n");
		}

		pre_shedule_wrie(key, time, count);
		//send(my_sock, time, count, 0);

		schedule_read(key);
	}
	else if (buffer == '4')
	{
		printf("Запрос *Информация об используемой памяти*...\n");

		char out_buf[8192];
		ZeroMemory(&out_buf, sizeof(out_buf));

		MEMORYSTATUSEX statex;
		char answer[1024];

		GlobalMemoryStatusEx(&statex);
		statex.dwLength = sizeof(statex);
		GlobalMemoryStatusEx(&statex);

		_itoa((int)statex.dwMemoryLoad, answer, 10);
		strcat(out_buf, "Percent of memory in use: ");
		strcat(out_buf, answer);
		strcat(out_buf, "\n");
		ZeroMemory(&answer, sizeof(answer));

		_i64toa(statex.ullTotalPhys / (1024 * 1024), answer, 10);
		strcat(out_buf, "Total MB of physical memory: ");
		strcat(out_buf, answer);
		strcat(out_buf, "\n");
		ZeroMemory(&answer, sizeof(answer));

		_i64toa(statex.ullAvailPhys / (1024 * 1024), answer, 10);
		strcat(out_buf, "Free MB of physical memory: ");
		strcat(out_buf, answer);
		strcat(out_buf, "\n");
		ZeroMemory(&answer, sizeof(answer));

		_i64toa(statex.ullTotalPageFile / (1024 * 1024), answer, 10);
		strcat(out_buf, "Total MB of paging file: ");
		strcat(out_buf, answer);
		strcat(out_buf, "\n");
		ZeroMemory(&answer, sizeof(answer));

		_i64toa(statex.ullAvailPageFile / (1024 * 1024), answer, 10);
		strcat(out_buf, "Free MB of paging file: ");
		strcat(out_buf, answer);
		strcat(out_buf, "\n");
		ZeroMemory(&answer, sizeof(answer));

		_i64toa(statex.ullTotalVirtual / (1024 * 1024), answer, 10);
		_i64toa(statex.ullAvailPageFile / (1024 * 1024), answer, 10);
		strcat(out_buf, "Total MB of virtual memory: ");
		strcat(out_buf, answer);
		strcat(out_buf, "\n");
		ZeroMemory(&answer, sizeof(answer));

		_i64toa(statex.ullAvailVirtual / (1024 * 1024), answer, 10);
		strcat(out_buf, "Free MB of virtual memory: ");
		strcat(out_buf, answer);
		strcat(out_buf, "\n");
		ZeroMemory(&answer, sizeof(answer));

		DWORD count = strlen(out_buf) + 1;
		if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)out_buf, &count, count))
		{
			printf("Encrypt: ERROR!\n");
		}

		//send(my_sock, out_buf, count, 0);
		pre_shedule_wrie(key, out_buf, count);

		schedule_read(key);
	}
	else if (buffer == '5')
	{
		printf("Запрос *Свободное место на локальных дисках*...\n");

		char temp[1024];
		char answer5[1024] = "";
		char *name_disk[] = { "C:", "D:", "E:", "F:", "G:", "H:", "I:", "J:", "K:", "L:",
			"M:", "N:", "O:", "P:", "Q:", "R:", "S:", "T:", "U:", " V:",
			"W:", "X:", "Y:", "Z:" };
		_int64 TotalNumberOfFreeBytes;
		strcpy(answer5, "Disks:\n");
		int flag;

		for (int i = 0; i < 24; i++)
		{
			wchar_t* wString = new wchar_t[4096];
			MultiByteToWideChar(CP_ACP, 0, name_disk[i], -1, wString, 4096);

			flag = GetDriveType(wString);

			if (flag == 3)
			{
				strcat(answer5, name_disk[i]);
				strcat(answer5, " - FIXED\n");

				TotalNumberOfFreeBytes = 0;
				GetDiskFreeSpaceEx(wString,
					(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);

				_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);

				strcat(answer5, "Free ");
				strcat(answer5, temp);
				strcat(answer5, " Gb\n");
			}
			else if (flag == 2)
			{
				strcat(answer5, name_disk[i]);
				strcat(answer5, " - REMOVABLE\n");

				TotalNumberOfFreeBytes = 0;
				GetDiskFreeSpaceEx(wString,
					(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);
				_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);

				strcat(answer5, "Free ");
				strcat(answer5, temp);
				strcat(answer5, " Gb\n");
			}
			else if (flag == 4)
			{
				strcat(answer5, name_disk[i]);
				strcat(answer5, " - REMOTE\n");

				TotalNumberOfFreeBytes = 0;
				GetDiskFreeSpaceEx(wString,
					(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);

				_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);

				strcat(answer5, "Free ");
				strcat(answer5, temp);
				strcat(answer5, " Gb\n");
			}
			else if (flag == 6)
			{
				strcat(answer5, name_disk[i]);
				strcat(answer5, " - RAMDISK\n");

				TotalNumberOfFreeBytes = 0;
				GetDiskFreeSpaceEx(wString,
					(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);

				_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);

				strcat(answer5, "Free ");
				strcat(answer5, temp);
				strcat(answer5, " Gb\n");
			}
			else if (flag == 5)
			{
				strcat(answer5, name_disk[i]);
				strcat(answer5, " - CDROM\n");

				TotalNumberOfFreeBytes = 0;
				GetDiskFreeSpaceEx(wString,
					(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);

				_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);

				strcat(answer5, "Free ");
				strcat(answer5, temp);
				strcat(answer5, " Gb\n");
			}
		}

		DWORD count = strlen(answer5) + 1;
		if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)answer5, &count, count))
		{
			printf("Encrypt: ERROR!\n");
		}

		//send(my_sock, answer5, count, 0);
		pre_shedule_wrie(key, answer5, count);

		ZeroMemory(&answer5, sizeof(answer5));

		schedule_read(key);
	}
	else if (buffer == '6') // for register: "k, machine"
	{
		printf("Запрос *Определить права доступа*...\n");

		char domain[256];
		char user[256];

		ACL_SIZE_INFORMATION acl_size;
		ACCESS_ALLOWED_ACE * pACE;
		PACL dacl;
		PSID pOwnerSID;

		char type;
		char buf;
		char path[128] = { 0 };
		char out_buf[8192];
		ZeroMemory(&out_buf, sizeof(out_buf));

		LPSTR SID_string;

		//schedule_read(key);
		//memcpy(&buf, g_ctxs[key].buf_recv, sizeof(buf));

		if (recv(g_ctxs[key].socket, &buf, sizeof(buf), 0) == 0)
		{
			strcat(out_buf, "GET_TYPE_OBJECT: ERROR!\n");

			printf("GET_TYPE_OBJECT: ERROR!\n");
		}
		else
		{
			if (buf == 'f') type = SE_FILE_OBJECT;
			if (buf == 'd') type = SE_FILE_OBJECT;
			if (buf == 'k') type = SE_REGISTRY_KEY;
		}

		//schedule_read(key);
		//memcpy((char *)&path, g_ctxs[key].buf_recv, sizeof(path));
		if (recv(g_ctxs[key].socket, (char *)&path, sizeof(path), 0) == 0)
		{
			strcat(out_buf, "GET_PATH_OBJECT: ERROR!\n");

			printf("GET_PATH_OBJECT: ERROR!\n");
		}
		if (GetNamedSecurityInfoA(path, (SE_OBJECT_TYPE)type, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &pOwnerSID) != ERROR_SUCCESS) {
			strcat(out_buf, "ACCESS ERROR!\n");

			printf("ACCESS ERROR!\n");
		}
		else
		{
			memset(out_buf, 0, 8192);

			GetAclInformation(dacl, &acl_size, sizeof(acl_size), AclSizeInformation);

			for (int i = 0; i < acl_size.AceCount; i++)
			{
				memset(domain, 0, 256);
				memset(user, 0, 256);

				DWORD userlen = sizeof(user);
				DWORD domlen = sizeof(domain);

				SID_NAME_USE sid_name;
				PSID pSID;
				LPSTR strSid = 0;

				GetAce(dacl, i, (PVOID *)&pACE);
				pSID = (PSID)(&(pACE->SidStart));

				SECURITY_INFORMATION si = GROUP_SECURITY_INFORMATION &
					LABEL_SECURITY_INFORMATION &
					DACL_SECURITY_INFORMATION &
					LABEL_SECURITY_INFORMATION &
					OWNER_SECURITY_INFORMATION;

				if (LookupAccountSidA(NULL, pSID, user, &userlen, domain, &domlen, &sid_name))
				{
					strcat(out_buf, "\nAccount: ");
					strcat(out_buf, domain);
					strcat(out_buf, "\\");
					strcat(out_buf, user);
					strcat(out_buf, " \n");
					strcat(out_buf, "Account's SID: ");
					ConvertSidToStringSidA(pSID, &SID_string);
					strcat(out_buf, SID_string);
					strcat(out_buf, " \n");
					strcat(out_buf, "ACE type: ");

					switch (pACE->Header.AceType)
					{
					case ACCESS_DENIED_ACE_TYPE:
						strcat(out_buf, "ACCESS: Denied\n");
						break;
					case ACCESS_ALLOWED_ACE_TYPE:
						strcat(out_buf, "ACCESS: Allowed\n");
						break;
					default:
						strcat(out_buf, "Audit\n");
					}

					/*
					strcat(out_buf, "Access mask: ");
					for (int j = 0; j < 32; j++)
					out_buf[strlen(out_buf)] = '0' + pACE->Mask / (1 << (31 - j)) % 2;
					*/
					strcat(out_buf, "Generic rights: \n");

					//generic rights
					if ((pACE->Mask & 1)) { strcat(out_buf, "GENERIC_READ\n"); }
					if ((pACE->Mask & 2)) { strcat(out_buf, "GENERIC_WRITE\n"); }
					if ((pACE->Mask & 4)) { strcat(out_buf, "GENERIC_EXECUTE\n"); }

					//standart rights
					strcat(out_buf, "Standard rights: \n");
					if ((pACE->Mask & SYNCHRONIZE)) { strcat(out_buf, "SYNCHRONIZE\n"); }
					if ((pACE->Mask & WRITE_OWNER)) { strcat(out_buf, "WRITE_OWNER\n"); }
					if ((pACE->Mask & WRITE_DAC)) { strcat(out_buf, "WRITE_DAC\n"); }
					if ((pACE->Mask & READ_CONTROL)) { strcat(out_buf, "READ_CONTROL\n"); }
					if ((pACE->Mask & DELETE)) { strcat(out_buf, "DELETE\n"); }

					if (type == SE_FILE_OBJECT)
					{
						if (buf == 'f')
						{
							strcat(out_buf, "Specific rights for file:\n");

							if ((pACE->Mask & FILE_READ_DATA)) { strcat(out_buf, "FILE_READ_DATA\n"); }
							if ((pACE->Mask & FILE_WRITE_DATA)) { strcat(out_buf, "FILE_WRITE_DATA\n"); }
							if ((pACE->Mask & FILE_APPEND_DATA)) { strcat(out_buf, "FILE_APPEND_DATA\n"); }
							if ((pACE->Mask & FILE_READ_EA)) { strcat(out_buf, "FILE_READ_EA\n"); }
							if ((pACE->Mask & FILE_WRITE_EA)) { strcat(out_buf, "FILE_WRITE_EA\n"); }
							if ((pACE->Mask & FILE_EXECUTE)) { strcat(out_buf, "FILE_EXECUTE\n"); }
							if ((pACE->Mask & FILE_READ_ATTRIBUTES)) { strcat(out_buf, "FILE_READ_ATTRIBUTES\n"); }
							if ((pACE->Mask & FILE_WRITE_ATTRIBUTES)) { strcat(out_buf, "FILE_WRITE_ATTRIBUTES\n"); }
						}
						if (buf == 'd')
						{
							strcat(out_buf, "Specific rights for directory:\n");

							if ((pACE->Mask & FILE_LIST_DIRECTORY)) { strcat(out_buf, "FILE_LIST_DIRECTORY\n"); }
							if ((pACE->Mask & FILE_ADD_FILE)) { strcat(out_buf, "FILE_ADD_FILE\n"); }
							if ((pACE->Mask & FILE_ADD_SUBDIRECTORY)) { strcat(out_buf, "FILE_ADD_SUBDIRECTORY\n"); }
							if ((pACE->Mask & FILE_READ_EA)) { strcat(out_buf, "FILE_READ_EA\n"); }
							if ((pACE->Mask & FILE_WRITE_EA)) { strcat(out_buf, "FILE_WRITE_EA\n"); }
							if ((pACE->Mask & FILE_TRAVERSE)) { strcat(out_buf, "FILE_TRAVERSE\n"); }
							if ((pACE->Mask & FILE_DELETE_CHILD)) { strcat(out_buf, "FILE_DELETE_CHILD\n"); }
							if ((pACE->Mask & FILE_READ_ATTRIBUTES)) { strcat(out_buf, "FILE_READ_ATTRIBUTES\n"); }
							if ((pACE->Mask & FILE_WRITE_ATTRIBUTES)) { strcat(out_buf, "FILE_WRITE_ATTRIBUTES\n"); }
						}
					}
					if (type == SE_REGISTRY_KEY)
					{
						strcat(out_buf, "Registry key rights:\n ");

						if ((pACE->Mask & KEY_CREATE_SUB_KEY))
						{
							strcat(out_buf, "KEY_CREATE_SUB_KEY\n ");
						}
						if (pACE->Mask & KEY_ENUMERATE_SUB_KEYS)
						{
							strcat(out_buf, "KEY_ENUMERATE_SUB_KEYS\n ");
						}
						if (pACE->Mask & KEY_NOTIFY)
						{
							strcat(out_buf, "KEY_NOTIFY\n ");
						}
						if (pACE->Mask & KEY_QUERY_VALUE)
						{
							strcat(out_buf, "KEY_QUERY_VALUE\n ");
						}
						if (pACE->Mask & KEY_SET_VALUE)
						{
							strcat(out_buf, "KEY_SET_VALUE\n ");
						}
					}
				}
			}
		}

		DWORD count = strlen(out_buf) + 1;
		if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)out_buf, &count, count))
		{
			printf("Encrypt: ERROR!\n");
		}

		pre_shedule_wrie(key, out_buf, count);
		//send(my_sock, out_buf, count, 0);

		schedule_read(key);
	}
	else if (buffer == '7')
	{
		printf("Запрос *Определить владельца файла*...\n");

		char stack[1024];
		ZeroMemory(&stack, sizeof(stack));

		DWORD dwRes = 0;
		PSID pOwnerSID;

		char path[128];
		char buf;
		char sid[1024];

		PSECURITY_DESCRIPTOR pSecDescr;

		//schedule_read(key);
		//memcpy(&buf, g_ctxs[key].buf_recv, sizeof(buf));
		recv(g_ctxs[key].socket, &buf, sizeof(buf), 0);

		//Sleep(100);///////////

		//schedule_read(key);
		//memcpy((char *)&path, g_ctxs[key].buf_recv, sizeof(path));
		recv(g_ctxs[key].socket, (char *)&path, sizeof(path), 0);

		//wchar_t* wString = new wchar_t[4096];
		//MultiByteToWideChar(CP_ACP, 0, path, -1, wString, 4096);

		if (buf == 'f')
		{
			dwRes = GetNamedSecurityInfoA(path, SE_FILE_OBJECT,
				OWNER_SECURITY_INFORMATION, &pOwnerSID, NULL, NULL, NULL, &pSecDescr);
		}
		else
		{
			dwRes = GetNamedSecurityInfoA(path, SE_REGISTRY_KEY,
				OWNER_SECURITY_INFORMATION, &pOwnerSID, NULL, NULL, NULL, &pSecDescr);
		}

		//HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (dwRes != ERROR_SUCCESS)
		{
			printf("Не получить SID владельца %i\n", GetLastError());//error
			LocalFree(pSecDescr);
		}

		char szOwnerName[1024];
		char szDomainName[1024];

		DWORD dwUserNameLength = sizeof(szOwnerName);
		DWORD dwDomainNameLength = sizeof(szDomainName);
		SID_NAME_USE sidUse;

		dwRes = LookupAccountSidA(NULL, pOwnerSID, szOwnerName, &dwUserNameLength,
			szDomainName, &dwDomainNameLength, &sidUse);

		if (dwRes == 0)
		{
			printf("ERROR!\n");
		}
		else
		{
			//printf("Owner name = %s\t Domain = %s\n", szOwnerName, szDomainName);
			strcat(stack, "Owner name: ");
			strcat(stack, szOwnerName);
			strcat(stack, "\n");
			strcat(stack, "Domain: ");
			strcat(stack, szDomainName);
			strcat(stack, "\n");

			LPWSTR SID = NULL;

			char name[1024] = "";

			BOOL flag = ConvertSidToStringSid(pOwnerSID, &SID);

			WideCharToMultiByte(CP_ACP, 0, SID, -1, name, sizeof(name), 0, 0);

			strcpy(sid, name);
			strcat(stack, "SID: ");
			strcat(stack, sid);
			strcat(stack, "\n");

			DWORD count = strlen(stack) + 1;
			CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)stack, &count, count);

			//send(my_sock, stack, count, 0); // HKEY_CURRENT_USER\Control Panel\Colors
			pre_shedule_wrie(key, stack, count);
		}

		schedule_read(key);
	}

	else if (*g_ctxs[key].buf_recv == '8')
	{
		printf("Отключился клиент...\n");

		//closesocket(my_sock);
		// Данные отправлены полностью, прервать все оммуникации,
		// добавить в порт событие на завершение работы
		CancelIo((HANDLE)g_ctxs[key].socket);
		PostQueuedCompletionStatus(g_io_port, 0, key,
			&g_ctxs[key].overlap_cancel);

		//count_client--;
		//printf("Клиентов: %d\n", count_client);
		//break;
	}
}


int main(int argc, char * argv[])
{
	setlocale(LC_ALL, "Russian");

	WSADATA ws;

	if (WSAStartup(MAKEWORD(2, 2), &ws))
	{
		// Tell the user that we could not find a usable Winsock DLL.
		printf("WSAStartup failed with error: %d\n", WSAGetLastError());
		return -1;
	}

	struct sockaddr_in addr;
	// Создание сокета прослушивания
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);

	// Создание порта завершения
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return -1;
	}
	// Обнуление структуры данных для хранения входящих соединений
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);

	addr.sin_addr.s_addr = htonl(INADDR_ANY); // INADDR_ANY - все локальные интерфейсы

	if (bind(s, (LPSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		// Ошибка в связывании. Пояснение можно получить функцией  WSAGetLastError().
		printf("Error bind %d\n", WSAGetLastError());
		closesocket(s);
		WSACleanup();
		return -1;
	}
	if (listen(s, SOMAXCONN) == SOCKET_ERROR)
	{
		// Ошибка. Пояснение можно получить функцией  WSAGetLastError().
		printf("Error listen %d\n", WSAGetLastError());
		closesocket(s);
		WSACleanup();
		return -1;
	}

	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return -1;
	}
	g_ctxs[0].socket = s;

	printf("Ожидание подключений…\n");

	// Старт операции принятия подключения.
	schedule_accept();
	// Бесконечный цикл принятия событий о завершенных операциях

	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED * lp_overlap;
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap,
			1);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;
				// Принятие подключения и начало принятия следующего
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента.
				// Ключ key - индекс в массиве g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					//char buffer = *g_ctxs[key].buf_recv;
					command_from_client(key, *g_ctxs[key].buf_recv);

				}

				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены
					g_ctxs[key].sz_send += transferred;

					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total &&
						transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
				}

				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf(" connection %u closed\n", key);
				}
			}
		}
		/*
		else
		{
		// Ни одной операции не было завершено в течение заданного времени, программа может
		// выполнить какие-либо другие действия
		// ...
		}
		*/
	}

	return 0;
}
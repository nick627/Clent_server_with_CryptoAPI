#include <WinSock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <iostream>

#pragma comment (lib, "ws2_32.lib")
#pragma warning(disable : 4996)

#define PORT (555)

int main(int argc, char * argv[])
{
	int time;
	int res = 0;
	int choice = 0;

	setlocale(LC_ALL, "Russian");

	WSADATA ws;
	SOCKET ClientSocket;

	if (WSAStartup(MAKEWORD(2, 2), &ws))
	{
		// Tell the user that we could not find a usable Winsock DLL.
		printf("WSAStartup failed with error: %d\n", WSAGetLastError());
		return -1;
	}
	
	if ((ClientSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		// Ошибка в создании сокета
		printf("Error socket %d\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}

	char addr[20];
	sockaddr_in ServerAddress;

	std::cout << "Введите IP-адрес сервера: "; // Просим ввести ip-адрес сервера
	std::cin >> addr; // Получаемего

	ServerAddress.sin_family = AF_INET; // TCP-IP соедение
	ServerAddress.sin_port = htons(PORT); // Порт
	ServerAddress.sin_addr.s_addr = inet_addr(addr); // Преобразуем адрес в нужный формат

	if (connect(ClientSocket, (SOCKADDR *)&ServerAddress, sizeof(ServerAddress)) == SOCKET_ERROR)
	{
		// Ошибка. Пояснение можно получить функцией  WSAGetLastError
		printf("Error connect %d\n", WSAGetLastError());
		return -1;
	}
	std::cout << "Соединение установлено c " << addr << std::endl << std::endl;

	HCRYPTPROV hProv;
	HCRYPTKEY hPubKey;
	HCRYPTKEY hSessionKey;
	BOOL success = TRUE;

	//if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	{
		printf("Не удается создать контекст\n");
	}

	// Генерация сессионного ключа
	if (!CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &hSessionKey))
	{
		std::cout << "CryptGenKey error" << std::endl;
	}

	else std::cout << "Session key generated" << std::endl;
	char buf[1024];
	char buf1[1024];
	int len;

	res = recv(ClientSocket, (char *)&buf, sizeof(buf), 0); // получили публичный ключ
	len = atoi(buf);
	res = recv(ClientSocket, (char *)&buf1, sizeof(buf1), 0);

	DWORD count = 0;

	if (!CryptImportKey(hProv, (BYTE *)buf1, len, 0, 0, &hPubKey))
	{
		std::cout << "CryptImportKey error" << std::endl;
	}
	else
	{
		std::cout << "Public Key's import completed" << std::endl;
	}

	// Получение размера массива, используемого для экспорта ключа
	if (!CryptExportKey(hSessionKey, hPubKey, SIMPLEBLOB, 0, NULL, &count))
	{
		std::cout << "CryptExportKey error" << std::endl;
	}

	// Инициализация массива, используемого для экспорта ключа
	//BYTE * data = static_cast<BYTE *>(malloc(count));
	BYTE * data = (BYTE *)(malloc(count));
	ZeroMemory(data, count);

	// Экспорт ключа шифрования
	if (!CryptExportKey(hSessionKey, hPubKey, SIMPLEBLOB, 0, data, &count)) // В data наш ключ
	{
		std::cout << "CryptExportKey error" << std::endl;
	}
	else
	{
		std::cout << "Session Key's export completed" << std::endl;
	}

	char size[1024];
	itoa((int)count, size, 10);
	send(ClientSocket, (char *)size, sizeof(size), 0);
	send(ClientSocket, (char *)data, count, 0); // Отправили зашифрованный сессионный ключ 

	while (choice != 8)
	{
		std::cout << "\nВыберите запрос:\n"
			<< "1. Тип и версия ОС\n"
			<< "2. Текущее время ОС\n"
			<< "3. Время, прошедшее с момента запуска ОС\n"
			<< "4. Информация об используемой памяти\n"
			<< "5. Свободное место на локальных дисках \n"
			<< "6. Права доступа \n"
			<< "7. Владелец файла \n"
			<< "8. Выход\n";
		std::cin >> choice;

		char buf;

		switch (choice)
		{
		case 1:
			buf = '1';

			char answer1[1024];
			ZeroMemory(&answer1, sizeof(answer1));

			send(ClientSocket, (char *)&buf, sizeof(buf), 0);

			DWORD cnt;
			cnt = recv(ClientSocket, (char *)&answer1, sizeof(answer1), 0);

			if (cnt <= 0)
			{
				std::cout << "Recv error \n" << std::endl;
				break;
			}

			std::cout << "\nCheck Encrypt:\n" << answer1 << std::endl;

			if (!CryptDecrypt(hSessionKey, 0, true, 0, (BYTE*)answer1, &cnt))
			{
				printf("Decrypt:ERROR!\n");
			}

			std::cout << "Версия ОС:\n" << answer1 << std::endl;

			//			ZeroMemory(&answer1, sizeof(answer1));
			break;
		case 2:
			buf = '2';

			char answer2[256];
			ZeroMemory(&answer2, sizeof(answer2));

			send(ClientSocket, (char *)&buf, sizeof(buf), 0);

			cnt = recv(ClientSocket, (char *)&answer2, sizeof(answer2), 0);

			if (cnt <= 0)
			{
				std::cout << "Recv error \n" << std::endl;
				break;
			}

			std::cout << "\nCheck Encrypt:\n" << answer2 << std::endl;

			if (!CryptDecrypt(hSessionKey, 0, true, 0, (BYTE *)answer2, &cnt))
			{
				printf("Decrypt:ERROR!\n");
			}

			std::cout << "Текущее время ОС:\n" << answer2 << std::endl;

			ZeroMemory(&answer2, sizeof(answer2));
			break;
		case 3:
			buf = '3';

			char answer3[256];
			ZeroMemory(&answer3, sizeof(answer3));

			send(ClientSocket, (char *)&buf, sizeof(buf), 0);

			cnt = recv(ClientSocket, (char *)&answer3, sizeof(answer3), 0);

			if (cnt <= 0)
			{
				std::cout << "Recv error \n" << std::endl;
				break;
			}

			std::cout << "\nCheck Encrypt:\n" << answer3 << std::endl;

			if (!CryptDecrypt(hSessionKey, 0, true, 0, (BYTE *)answer3, &cnt))
			{
				printf("Decrypt:ERROR!\n");
			}

			time = atoi(answer3);
			std::cout << "Время, прошедшее с момента запуска:\n" << std::endl;
			std::cout << "Hours:" << time / 3600000 % 24 << " Minutes:" << time / 60000 % 60 << " Seconds:" << time / 1000 % 60 << std::endl;

			break;
		case 4:
			buf = '4';

			char answer4[8192];
			ZeroMemory(&answer4, sizeof(answer4));

			send(ClientSocket, (char *)&buf, sizeof(buf), 0);

			cnt = recv(ClientSocket, (char *)&answer4, sizeof(answer4), 0);

			if (cnt <= 0)
			{
				std::cout << "Recv error \n" << std::endl;
				break;
			}

			std::cout << "\nCheck Encrypt:\n" << answer4 << std::endl;

			if (!CryptDecrypt(hSessionKey, 0, true, 0, (BYTE*)answer4, &cnt))
			{
				printf("Decrypt:ERROR!\n");
			}

			std::cout << answer4 << std::endl;

			break;
		case 5:
			buf = '5';

			char answer5[1024];
			ZeroMemory(&answer5, sizeof(answer5));

			send(ClientSocket, (char *)&buf, sizeof(buf), 0);

			cnt = recv(ClientSocket, (char *)&answer5, sizeof(answer5), 0);

			if (cnt <= 0)
			{
				std::cout << "Recv error \n" << std::endl;
				break;
			}

			std::cout << "\nCheck Encrypt:\n" << answer5 << std::endl;

			if (!CryptDecrypt(hSessionKey, 0, true, 0, (BYTE *)answer5, &cnt))
			{
				printf("Decrypt:ERROR!\n");
			}

			std::cout << answer5 << std::endl;
			break;
		case 6:
			buf = '6';

			char path6[128];
			char s;

			char answer6[8192];
			ZeroMemory(&answer6, sizeof(answer6));

			send(ClientSocket, (char *)&buf, sizeof(buf), 0);

			printf("\nEnter Object Type:\nFile - [f]\nDirectory - [d]\nRegistry Key - [k]\nEnter: ");
			std::cin >> s;
			send(ClientSocket, (char *)&s, sizeof(char), 0);

			std::cout << "Enter the path to the object: " << std::endl;
			std::cin >> path6;

			send(ClientSocket, path6, sizeof(path6), 0);
			std::cout << "Path: " << path6 << std::endl;

			cnt = recv(ClientSocket, (char *)&answer6, sizeof(answer6), 0);

			if (cnt <= 0)
			{
				std::cout << "Recv error \n" << std::endl;
				break;
			}

			std::cout << "\nCheck Encrypt:\n" << answer6 << std::endl;

			if (!CryptDecrypt(hSessionKey, 0, true, 0, (BYTE*)answer6, &cnt))
			{
				printf("Decrypt:ERROR!\n");
			}

			std::cout << answer6 << " " << std::endl;

			break;
		case 7:
			buf = '7';

			char path[128];
			char c;

			char answer7[1024];
			ZeroMemory(&answer7, sizeof(answer7));

			send(ClientSocket, (char *)&buf, sizeof(buf), 0);

			printf("Enter Object Type:\nFile or Directory - [f]\nRegistry Key - [k]\nEnter: ");
			std::cin >> c;
			send(ClientSocket, (char *)&c, sizeof(char), 0);

			std::cout << "Enter the path to the object: " << std::endl;
			std::cin >> path;
			send(ClientSocket, path, sizeof(path), 0);

			cnt = recv(ClientSocket, (char *)&answer7, sizeof(answer7), 0);

			if (cnt <= 0)
			{
				std::cout << "Recv error \n" << std::endl;
				break;
			}

			std::cout << "\nCheck Encrypt:\n" << answer7 << std::endl;

			if (!CryptDecrypt(hSessionKey, 0, true, 0, (BYTE*)answer7, &cnt))
			{
				printf("Decrypt:ERROR!\n");
			}

			std::cout << answer7 << std::endl;

			break;
		case 8:
			buf = '8';

			send(ClientSocket, (char *)&buf, sizeof(buf), 0);

			break;
		default:
			std::cout << "Error" << std::endl;
			break;
		}
	}

	closesocket(ClientSocket);

	WSACleanup();
	return 0;
}
#include <locale>
#include <codecvt>
#include <string>
#include <sstream>
#pragma comment(lib, "ws2_32.lib")
#include <Winsock2.h>
#pragma comment(lib, "Bthprops.lib")
#include <Ws2bth.h>
using namespace std;

SOCKET bt;

void connect(string deviceName) {
    WSAQUERYSET     wsaQuery{};
    LPWSAQUERYSET   pwsaResults{};
    HANDLE          hLookup{};

    CSADDR_INFO* pAddrInfo{};
    SOCKADDR_BTH* pBtSockRemote{},
        * pBtSockLocal{};

    char    buffer[4096] = {};
    int     nDevicesFound = 1;
    DWORD   swSize = sizeof(buffer);
    DWORD   flags = LUP_RETURN_ADDR | LUP_RETURN_NAME | LUP_RES_SERVICE | LUP_CONTAINERS | LUP_RETURN_BLOB | LUP_RETURN_TYPE;
    wsaQuery.dwNameSpace = NS_BTH;
    wsaQuery.dwSize = sizeof(WSAQUERYSET);
    unsigned int aaddr[6];
    WSADATA wsa;
    memset(&wsa, 0, sizeof(wsa));
    WSAStartup(MAKEWORD(2, 2), &wsa);
    WSALookupServiceBegin(&wsaQuery, flags, &hLookup);
    pwsaResults = (LPWSAQUERYSET)buffer;
    pwsaResults->dwNameSpace = NS_BTH;
    pwsaResults->dwSize = sizeof(WSAQUERYSET);
    while (WSALookupServiceNext(hLookup, flags, &swSize, pwsaResults) == NO_ERROR)
    {
        pAddrInfo = (CSADDR_INFO*)pwsaResults->lpcsaBuffer;
        pBtSockRemote = (SOCKADDR_BTH*)(pwsaResults->lpcsaBuffer->RemoteAddr.lpSockaddr);
        using convert_type = codecvt_utf8<wchar_t>;
        wstring_convert<convert_type, wchar_t> converter;
        if ((pwsaResults->dwOutputFlags & BTHNS_RESULT_DEVICE_AUTHENTICATED) > 0 == 1 && converter.to_bytes(pwsaResults->lpszServiceInstanceName) == deviceName) {
            stringstream s;
            s << hex << GET_NAP(pBtSockRemote->btAddr) << hex << GET_SAP(pBtSockRemote->btAddr);
            string addr;
            for (int i = 0; i < 6; i++) {
                addr = addr + s.str()[i * 2] + s.str()[i * 2 + 1];
                if (i < 5) {
                    addr = addr + ":";
                }
            }
            bt = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
            SOCKADDR_BTH sockAddr;
            memset(&sockAddr, 0, sizeof(sockAddr));
            sockAddr.addressFamily = AF_BTH;
            sockAddr.serviceClassId = RFCOMM_PROTOCOL_UUID;
            sockAddr.port = BT_PORT_ANY;
            BTH_ADDR tmpaddr = 0;
            char caddr[18];
            strcpy_s(caddr, addr.c_str());
            sscanf_s(caddr, "%02x:%02x:%02x:%02x:%02x:%02x", &aaddr[0], &aaddr[1], &aaddr[2], &aaddr[3], &aaddr[4], &aaddr[5]);
            *&sockAddr.btAddr = 0;
            for (int i = 0; i < 6; i++) {
                tmpaddr = (BTH_ADDR)(aaddr[i] & 0xff);
                *&sockAddr.btAddr = ((*&sockAddr.btAddr) << 8) + tmpaddr;
            }
            connect(bt, (SOCKADDR*)&sockAddr, sizeof(sockAddr));
            cout << WSAGetLastError();
        }
        nDevicesFound++;
    }
    WSALookupServiceEnd(hLookup);
};

void send(string text {
    char buf[100];
    strcpy_s(buf, text.c_str());
    send(bt, buf, (int)strlen(buf), 0);
}

int ascii(string str)
{
    int l = str.length();
    int convert;
    for (int i = 0; i < l; i++) {
        convert = str[i] - NULL;
        return convert;
    }
}

string recv() {
    string buf;
    char c[2];
    int numBytes;
    while (true) {
        numBytes = recv(bt, c, 1, 0);
        if (numBytes > 0) {
            c[numBytes] = '\0';
            if (ascii(c) == 10) {
                return buf;
                break;
            }
            else {
                buf += c;
            }
        }
    }
}

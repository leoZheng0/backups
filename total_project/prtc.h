#pragma once
#include <WinSock2.h>
#include <Windows.h>

#include<vector>
#include<string>
#include<iostream>
using namespace std;
#pragma warning(disable:4996)
#define HAVE_REMOTE
#include <pcap.h>
#include "remote-ext.h"
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
//28�ֽ�ARP֡�ṹ
#pragma pack(1) // �����ֽڶ���ģʽ
typedef struct ArpHeader
{
	WORD hardwareType;  // Ӳ������
	WORD protocolType;  //  Э������
	BYTE hLen;  //  Ӳ����ַ����
	BYTE pLen;  //  Э���ַ����
	WORD operation; //  ��������
	BYTE sendHa[6]; //  ���Ͷ�Ӳ����ַ
	DWORD sendIP;   //  ���Ͷ�IP��ַ
	BYTE recvHa[6]; //  ���ն�Ӳ����ַ
	DWORD recvIP;   //  ���ն�IP��ַ
};

//14�ֽ���̫���ײ�
typedef struct EthernetHeader
{
	BYTE dstMac[6]; // Ŀ��MAC��ַ
	BYTE srcMac[6]; // ԴMAC��ַ
	WORD type;      // ����
};

//��������arp���İ����ܳ���42�ֽ�

typedef struct ArpPacket {
	EthernetHeader fh;
	ArpHeader ap;
};

typedef struct ip_header//ipͷ
{
	char version : 4;
	char headerlength : 4;
	char cTOS;
	unsigned short totla_length;
	unsigned short identification;
	unsigned short flags_offset;
	char time_to_live;
	char Protocol;
	unsigned short check_sum;
	unsigned int SrcAddr;
	unsigned int DstAddr;
}ip_header;



//������һ��ʵ��
#define LAB2
//ʵ��ר�������ͺ���
#ifdef LAB2
//ʵ�����
void lab2();
#define BROADCAST_MAC { 0xff,0xff,0xff,0xff,0xff,0xff }
#define FAKE_MAC { 0x0f,0x0f,0x0f,0x0f,0x0f,0x0f }
#define ARP_REQUEST htons(0x0001)
#define ARP_REPLY htons(0x0002)
#define FAKE_IP "112.112.112.112"

u_char* makeARPPacket(u_char* dstMac, u_char* srcMac, WORD operation, const char* srcIP, const char* dstIP);
bool macCompare(BYTE* mac1, BYTE* mac2);

u_char sip[16] = { 0,0,0,0 };
u_char smac[6*4] = { 0,0,0,0,0,0 };
#endif // 


//����������
std::vector<pcap_if_t*> get_adapters();//��ȡ�����б�
//����������
std::vector<pcap_if_t*> adapters;//�����б�
std::vector<char*> ipList;//ip��ַ��list,��Ŷ�Ӧ�����б�
int which_adapter = 0;//�û�ָ��Ҫ��һ������
pcap_t* adhandle;              // ���������
struct pcap_pkthdr* header;    // ��̫������֡ͷ
const u_char* pkt_data;        // ��̫�����ݰ�


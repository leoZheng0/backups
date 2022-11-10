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
//28字节ARP帧结构
#pragma pack(1) // 进入字节对齐模式
typedef struct ArpHeader
{
	WORD hardwareType;  // 硬件类型
	WORD protocolType;  //  协议类型
	BYTE hLen;  //  硬件地址长度
	BYTE pLen;  //  协议地址长度
	WORD operation; //  操作类型
	BYTE sendHa[6]; //  发送端硬件地址
	DWORD sendIP;   //  发送端IP地址
	BYTE recvHa[6]; //  接收端硬件地址
	DWORD recvIP;   //  接收端IP地址
};

//14字节以太网首部
typedef struct EthernetHeader
{
	BYTE dstMac[6]; // 目的MAC地址
	BYTE srcMac[6]; // 源MAC地址
	WORD type;      // 类型
};

//定义整个arp报文包，总长度42字节

typedef struct ArpPacket {
	EthernetHeader fh;
	ArpHeader ap;
};

typedef struct ip_header//ip头
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



//定义哪一个实验
#define LAB2
//实验专属变量和函数
#ifdef LAB2
//实验序号
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


//函数定义区
std::vector<pcap_if_t*> get_adapters();//获取网卡列表
//常量定义区
std::vector<pcap_if_t*> adapters;//网卡列表
std::vector<char*> ipList;//ip地址的list,序号对应网卡列表
int which_adapter = 0;//用户指定要哪一块网卡
pcap_t* adhandle;              // 适配器句柄
struct pcap_pkthdr* header;    // 以太网数据帧头
const u_char* pkt_data;        // 以太网数据包



#include "prtc.h"

std::vector<pcap_if_t*> get_adapters() {//获得所有网卡设备的指针vector
	pcap_if_t* allAdapters;    // 所有网卡设备保存,本质上是一个头指针,可以遍历访问以后的设备
	pcap_if_t* p;            // 用于遍历的指针
	std::vector<pcap_if_t*> adapters;
	int index = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 获取本地机器设备列表 */
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
	{
		/* 打印网卡信息列表 */
		for (p = allAdapters; p != NULL; p = p->next, ++index)
		{
			printf("网卡地址: %x 网卡ID: %s \n", p->addresses, p->name);
			if (p->description)
				printf("ID: %d --> Name: %s \n", index, p->description);
			adapters.push_back(p);
			for (pcap_addr_t* a = p->addresses; a != NULL; a = a->next)
			{
				if (a->addr->sa_family == AF_INET) // 判断该地址是否为IP地址
				{
					// 获取IP地址
					ipList.push_back(new char[strlen(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr)) + 1]{ 0 });
					strcpy_s(ipList[ipList.size() - 1], strlen(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr)) + 1, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				}
			}
		}
	}

	/* 不再需要设备列表了，释放它 */
	pcap_freealldevs(allAdapters);
	return adapters;
}
/* 整合ARP数据包
 * @param u_char* dstMac: 数据包目的Mac地址，ARP请求中没有意义
 * @param u_char* srcMac: 数据包源Mac地址
 * @param WORD operation: ARP类型 1为ARP请求 2为ARP应答
 * @param const char* srcIP: 源IP地址
 * @param const char* dstIP: 目的IP地址
 */

int main() {
	adapters = get_adapters();//获取网卡信息
	std::cout << "请输入需要监视的网卡:" << std::endl;
	std::cin >> which_adapter;

	if ((adhandle = pcap_open(adapters[which_adapter]->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, 0)) == NULL)
	{
		return -1;
	}
	printf("已开始监视:第%d块网卡\n",which_adapter );
#ifdef LAB2
	lab2();
#endif
}


#ifdef LAB2
/* MAC地址比较 */
bool macCompare(BYTE* mac1, BYTE* mac2)
{
	for (int i = 0; i < 6; i++)
	{
		if (mac1[i] != mac2[i])
			return false;
	}
	return true;
}
u_char* makeARPPacket(u_char* dstMac, u_char* srcMac, WORD operation, const char* srcIP, const char* dstIP)
{
	struct ArpPacket arpData[42];
	// 设置以太网帧的目的Mac地址
	//u_char dstMac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
	memcpy(arpData->fh.dstMac, dstMac, 6);
	// 设置以太网帧的源Mac地址
	//u_char srcMac[6] = { 0x0f,0x0f,0x0f,0x0f,0x0f,0x0f };   // 这里使用伪造的本机Mac地址
	memcpy(arpData->fh.srcMac, srcMac, 6);

	// 设置以太网帧的类型为ARP，不修改
	arpData->fh.type = htons(0x0806);
	// 设置ARP数据包硬件类型为以太网，不修改
	arpData->ap.hardwareType = htons(0x0001);
	// 设置ARP数据包协议类型为IPV4，不修改
	arpData->ap.protocolType = htons(0x0800);
	// 设置ARP数据包硬件地址长度为6，不修改
	arpData->ap.hLen = 6;
	// 设置ARP数据包协议地址长度为4，不修改
	arpData->ap.pLen = 4;

	// 设置ARP数据包操作码为ARP请求
	arpData->ap.operation = operation;
	// 设置ARP数据包的源Mac地址
	memcpy(arpData->ap.sendHa, srcMac, 6);
	// 设置ARP数据包的源IP地址
	arpData->ap.sendIP = inet_addr(srcIP);
	// 设置ARP数据包的目的Mac地址
	//u_char reqDstMac[6] = { 0x0,0x0,0x0,0x0,0x0,0x0 };
	memcpy(arpData->ap.recvHa, dstMac, 6);   // arp请求中该项没有意义
	// 设置ARP数据包的目的IP地址
	arpData->ap.recvIP = inet_addr(dstIP);

	return (u_char*)arpData;
}
void lab2() {
	//打印一下信息
	strcpy((char*)sip, ipList[which_adapter]);
	printf("本机ip为: %s\n", sip);
	//先获取本机mac地址
	u_char dstMac[6] = BROADCAST_MAC;
	u_char srcMac[6] = FAKE_MAC;
	u_char* broadcastArpData = makeARPPacket(dstMac, srcMac, ARP_REQUEST, (char*)sip, (char*)sip); // 向本机发送虚构地址的ARP请求数据包
	pcap_sendpacket(adhandle, broadcastArpData, 42);//广播出去,获得自己的mac地址
	//开始接收arp数据包
	int res = 0;
	struct ArpPacket* query_myself = new ArpPacket;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		/* 超时继续 */
		if (res == 0)
		{
			continue;
		}
		/* 分析捕获的唯一ARP数据包 */
		struct ArpPacket* caughtArpData = (struct ArpPacket*)pkt_data;
		WORD caughtPacketType = ntohs(caughtArpData->fh.type);
		WORD operation = caughtArpData->ap.operation;
		memcpy_s(smac, 6, caughtArpData->fh.srcMac, 6);
		memcpy(query_myself, caughtArpData,42);
		if (res == 1 && caughtPacketType == 0x0806 && operation == ARP_REPLY)   // 判断捕获的ARP数据包为ARP类型，且为ARP响应
		{
			printf("本机mac为: %02x-%02x-%02x-%02x-%02x-%02x\n", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
			break;
		}
	}

	while (1)
	{
		char dstIP[16] = { 0 };
		printf("\n输入你想查询的ip: ");
		scanf_s("%s", dstIP, 16);
		/* 分析查询的IP地址是否与打开网卡相同，若查询本机则使用虚构的MAC和IP地址，否则使用本机的MAC和IP地址填入发送端*/
		if (strncmp((char*)sip, dstIP,strlen(dstIP)))
		{
			/* 查询远端网卡 */
			memcpy_s(srcMac, 6, smac, 6);
			broadcastArpData = makeARPPacket(dstMac, srcMac, ARP_REQUEST, (char*)sip, dstIP);
			pcap_sendpacket(adhandle, broadcastArpData, 42);
			while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
			{
				if (res == 0) continue;
				struct ArpPacket* caughtArpData = (struct ArpPacket*)pkt_data;
				WORD caughtPacketType = ntohs(caughtArpData->fh.type);
				BYTE caughtSrcMac[6];
				memcpy_s(caughtSrcMac, 6, caughtArpData->fh.srcMac, 6);
				WORD operation = caughtArpData->ap.operation;
				if (res == 1 && caughtPacketType == 0x0806 && operation == ARP_REPLY && !macCompare(caughtSrcMac,smac))   // 判断捕获的ARP数据包为ARP类型，且为ARP响应，且捕获的源MAC地址不为本机MAC地址
				{
					printf("Caught mac address: %02x-%02x-%02x-%02x-%02x-%02x\n", caughtSrcMac[0], caughtSrcMac[1], caughtSrcMac[2], caughtSrcMac[3], caughtSrcMac[4], caughtSrcMac[5]);
					break;
				}
			}
			if (res == -1)
			{
				printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
				exit(-1);
			}
		}
		else
		{
			/* 查询本机 */ 
			printf("本机mac为: %02x-%02x-%02x-%02x-%02x-%02x\n", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
		}
	}
}
#endif


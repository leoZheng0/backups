
#include "prtc.h"

std::vector<pcap_if_t*> get_adapters() {//������������豸��ָ��vector
	pcap_if_t* allAdapters;    // ���������豸����,��������һ��ͷָ��,���Ա��������Ժ���豸
	pcap_if_t* p;            // ���ڱ�����ָ��
	std::vector<pcap_if_t*> adapters;
	int index = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* ��ȡ���ػ����豸�б� */
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
	{
		/* ��ӡ������Ϣ�б� */
		for (p = allAdapters; p != NULL; p = p->next, ++index)
		{
			printf("������ַ: %x ����ID: %s \n", p->addresses, p->name);
			if (p->description)
				printf("ID: %d --> Name: %s \n", index, p->description);
			adapters.push_back(p);
			for (pcap_addr_t* a = p->addresses; a != NULL; a = a->next)
			{
				if (a->addr->sa_family == AF_INET) // �жϸõ�ַ�Ƿ�ΪIP��ַ
				{
					// ��ȡIP��ַ
					ipList.push_back(new char[strlen(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr)) + 1]{ 0 });
					strcpy_s(ipList[ipList.size() - 1], strlen(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr)) + 1, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				}
			}
		}
	}

	/* ������Ҫ�豸�б��ˣ��ͷ��� */
	pcap_freealldevs(allAdapters);
	return adapters;
}
/* ����ARP���ݰ�
 * @param u_char* dstMac: ���ݰ�Ŀ��Mac��ַ��ARP������û������
 * @param u_char* srcMac: ���ݰ�ԴMac��ַ
 * @param WORD operation: ARP���� 1ΪARP���� 2ΪARPӦ��
 * @param const char* srcIP: ԴIP��ַ
 * @param const char* dstIP: Ŀ��IP��ַ
 */

int main() {
	adapters = get_adapters();//��ȡ������Ϣ
	std::cout << "��������Ҫ���ӵ�����:" << std::endl;
	std::cin >> which_adapter;

	if ((adhandle = pcap_open(adapters[which_adapter]->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, 0)) == NULL)
	{
		return -1;
	}
	printf("�ѿ�ʼ����:��%d������\n",which_adapter );
#ifdef LAB2
	lab2();
#endif
}


#ifdef LAB2
/* MAC��ַ�Ƚ� */
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
	// ������̫��֡��Ŀ��Mac��ַ
	//u_char dstMac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
	memcpy(arpData->fh.dstMac, dstMac, 6);
	// ������̫��֡��ԴMac��ַ
	//u_char srcMac[6] = { 0x0f,0x0f,0x0f,0x0f,0x0f,0x0f };   // ����ʹ��α��ı���Mac��ַ
	memcpy(arpData->fh.srcMac, srcMac, 6);

	// ������̫��֡������ΪARP�����޸�
	arpData->fh.type = htons(0x0806);
	// ����ARP���ݰ�Ӳ������Ϊ��̫�������޸�
	arpData->ap.hardwareType = htons(0x0001);
	// ����ARP���ݰ�Э������ΪIPV4�����޸�
	arpData->ap.protocolType = htons(0x0800);
	// ����ARP���ݰ�Ӳ����ַ����Ϊ6�����޸�
	arpData->ap.hLen = 6;
	// ����ARP���ݰ�Э���ַ����Ϊ4�����޸�
	arpData->ap.pLen = 4;

	// ����ARP���ݰ�������ΪARP����
	arpData->ap.operation = operation;
	// ����ARP���ݰ���ԴMac��ַ
	memcpy(arpData->ap.sendHa, srcMac, 6);
	// ����ARP���ݰ���ԴIP��ַ
	arpData->ap.sendIP = inet_addr(srcIP);
	// ����ARP���ݰ���Ŀ��Mac��ַ
	//u_char reqDstMac[6] = { 0x0,0x0,0x0,0x0,0x0,0x0 };
	memcpy(arpData->ap.recvHa, dstMac, 6);   // arp�����и���û������
	// ����ARP���ݰ���Ŀ��IP��ַ
	arpData->ap.recvIP = inet_addr(dstIP);

	return (u_char*)arpData;
}
void lab2() {
	//��ӡһ����Ϣ
	strcpy((char*)sip, ipList[which_adapter]);
	printf("����ipΪ: %s\n", sip);
	//�Ȼ�ȡ����mac��ַ
	u_char dstMac[6] = BROADCAST_MAC;
	u_char srcMac[6] = FAKE_MAC;
	u_char* broadcastArpData = makeARPPacket(dstMac, srcMac, ARP_REQUEST, (char*)sip, (char*)sip); // �򱾻������鹹��ַ��ARP�������ݰ�
	pcap_sendpacket(adhandle, broadcastArpData, 42);//�㲥��ȥ,����Լ���mac��ַ
	//��ʼ����arp���ݰ�
	int res = 0;
	struct ArpPacket* query_myself = new ArpPacket;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		/* ��ʱ���� */
		if (res == 0)
		{
			continue;
		}
		/* ���������ΨһARP���ݰ� */
		struct ArpPacket* caughtArpData = (struct ArpPacket*)pkt_data;
		WORD caughtPacketType = ntohs(caughtArpData->fh.type);
		WORD operation = caughtArpData->ap.operation;
		memcpy_s(smac, 6, caughtArpData->fh.srcMac, 6);
		memcpy(query_myself, caughtArpData,42);
		if (res == 1 && caughtPacketType == 0x0806 && operation == ARP_REPLY)   // �жϲ����ARP���ݰ�ΪARP���ͣ���ΪARP��Ӧ
		{
			printf("����macΪ: %02x-%02x-%02x-%02x-%02x-%02x\n", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
			break;
		}
	}

	while (1)
	{
		char dstIP[16] = { 0 };
		printf("\n���������ѯ��ip: ");
		scanf_s("%s", dstIP, 16);
		/* ������ѯ��IP��ַ�Ƿ����������ͬ������ѯ������ʹ���鹹��MAC��IP��ַ������ʹ�ñ�����MAC��IP��ַ���뷢�Ͷ�*/
		if (strncmp((char*)sip, dstIP,strlen(dstIP)))
		{
			/* ��ѯԶ������ */
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
				if (res == 1 && caughtPacketType == 0x0806 && operation == ARP_REPLY && !macCompare(caughtSrcMac,smac))   // �жϲ����ARP���ݰ�ΪARP���ͣ���ΪARP��Ӧ���Ҳ����ԴMAC��ַ��Ϊ����MAC��ַ
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
			/* ��ѯ���� */ 
			printf("����macΪ: %02x-%02x-%02x-%02x-%02x-%02x\n", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
		}
	}
}
#endif


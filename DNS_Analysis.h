#ifndef DNS_ANALYSIS_H
#define DNS_ANALYSIS_H

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include<iostream>
#include<string>
#include<WinSock2.h>
#include<vector>
#pragma comment(lib,"ws2_32.lib")

#define _DNS_SEVER_PORT_ 53//DNS�˿�
#define _MAX_RECV_PACKAGE_SIZE_  512

/*RFC1035 3~4*/
namespace DNS_Request_Protocol
{
	struct DNSRequestHeader
	{
		unsigned short transationID;               //��������ID,�Զ���
		unsigned short flag;                        //��־λ
		/*
		QR ����0/��Ӧ1	1λ
		Opcode 0��׼��ѯ��1�����ѯ��2״̬����	4λ
		AA Ȩ��������1/����0	1λ
		TC �ضϣ���512�ֽڷ���ǰ512��1/����0	1λ
		RD �����ݹ飬����ݹ��ҵ�1/����0�������ܽ��ķ������б�	1λ
		RA ���õݹ飬����������1��֧�ֵݹ�/����0	1λ
		Z ����������Ϊ0�����ۿͻ��˻��Ƿ�����	3λ
		rcode ����ʾ��0��ȷ��1��ʽ����2������ʧ�ܣ�3���ִ��������岻���ڣ�4��֧�ֲ�ѯ���ͣ�5�ܾ�����Ӧ��	4λ
		*/
		unsigned short QDCount;             //ѯ���������/�ͻ���
		unsigned short ANCount;				 //�ش��������/������
		unsigned short NSCount;						//Ȩ�����Ʒ���������
		unsigned short NACount;                        //������Դ����(Ȩ����������Ӧip��)
	};
	struct DNSRequestModule
	{
		std::string nameBuff_;
		/*һ���ʽ (RFC1035 4.1.2)
				��ǩ���ݳ���(1���ֽ�) + ��ǩ���ݣ��Ա�ǩ���ݳ���0��ΪName�Ľ����������磺
				03www05pivix03net00��ĸ����
		  ��Ϣѹ����ʽ (RFC1035 4.1.4)
				�����ǩ���ݳ��ȵĶ�����ǰ��λ��11�����ʾ��Ϣѹ����(ֻ����Ƕ�������ֽڣ�Ҫ��ƫ�ƣ�ƫ�ƿ�ʼ������00)
				��ʱ����ǩ���ݳ���1���ֽ�+�����1���ֽ�һ��16λ����14λ��ʾ���DNS����ʼ��ַ��ƫ��(Byte)�����磺
				03www05pivix(0x)c1f3��ʱc0��11��ͷĩβѹ���ھ��뱨��ͷ1f3��..........  .net00��00��β
				RFC1035�й涨��֧�ֵ���Ϣѹ������Ϊ��
				�������ݳ���0��β�ı�ǩ����
				��ƫ��ָ��
				�۱�ǩ����+ƫ��ָ��
				Ҳ����˵��Name����Ϣѹ��Ҫ��ƫ��ָ�������Name��β�����Ҳ�֧��ͬһ�����ڶ��ƫ��ָ��(ƫ��ָ������)��
				��Name����Ϣѹ��֧��Ƕ�׵�ƫ��ָ�룬��ָ��ָ���ƫ��λ����Ȼ����ƫ��ָ���β������
		*/
		unsigned short type_;     //TYPE=1��ʾ����IP��ַ��TYPE=5��ʾCNAME
		unsigned short class_;    //һ�������CLASS=1��ʾInternet 
	};
	struct DNSResponedAnswerModule
	{
		std::string nameBuff_;
		unsigned short type_;     //TYPE=1��ʾ����IP��ַ��TYPE=5��ʾCNAME
		unsigned short class_;    //һ�������CLASS=1��ʾInternet 
		int TTL_;        //����ʱ��
		unsigned short DataLength_;//Data�ֽ���
		std::string Data_;//Data
	};
	struct DNSResponedAuthorityNSModule
	{

	};
	struct DNSResponedNSAddMsgModule
	{

	};
}


class DNS_Analysis
{
public:
	DNS_Analysis(std::string dnsSeverIP);
	std::vector<std::string> DNS_Request(std::string name);
	void printimformation();
	std::vector<DNS_Request_Protocol::DNSResponedAnswerModule> AnswerModules;
private:
	void CreatPackage(std::string& package, std::string& name);	//��ֻ�ṩһ��������ѯ
	DNS_Request_Protocol::DNSRequestHeader GetHeader(std::string& recvBuff);
	DNS_Request_Protocol::DNSRequestModule  GetRequest(std::string& recvBuff);  //��ʵ������
	std::vector<DNS_Request_Protocol::DNSResponedAnswerModule> GetAnswerModule(std::string& recvBuff, int num);
	inline bool is_cutdown(DNS_Request_Protocol::DNSRequestHeader header);
	inline std::string regularName(std::string& oldname);
	inline bool is_zip(std::string::iterator& pos, std::string& recvBuff,unsigned char& c);
	inline void poscopy(std::string::iterator pos, char* position,int Len);
	std::string GetName(std::string::iterator& pos, std::string& recvBuff);
	DNS_Analysis() = default;
	bool valid;
	WSADATA wsaData;
	WORD wVersionRequested;
	SOCKET dnsSever;
	sockaddr_in dnsSeverAddr;
	int sockaddr_in_Len;
private:
	int package_size;
};

#endif


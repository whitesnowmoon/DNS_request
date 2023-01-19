#ifndef DNS_ANALYSIS_H
#define DNS_ANALYSIS_H

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include<iostream>
#include<string>
#include<WinSock2.h>
#include<vector>
#pragma comment(lib,"ws2_32.lib")

#define _DNS_SEVER_PORT_ 53//DNS端口
#define _MAX_RECV_PACKAGE_SIZE_  512

/*RFC1035 3~4*/
namespace DNS_Request_Protocol
{
	struct DNSRequestHeader
	{
		unsigned short transationID;               //事务名称ID,自定义
		unsigned short flag;                        //标志位
		/*
		QR 请求0/响应1	1位
		Opcode 0标准查询，1反向查询，2状态请求	4位
		AA 权威服务器1/否则0	1位
		TC 截断，超512字节返回前512个1/否则0	1位
		RD 期望递归，必须递归找到1/否则0，返回能解答的服务器列表	1位
		RA 可用递归，服务器返回1则支持递归/否则0	1位
		Z 保留，必须为0，无论客户端还是服务器	3位
		rcode 差错表示，0正确，1格式错误，2服务器失败，3名字错误，无意义不存在，4不支持查询类型，5拒绝，不应答	4位
		*/
		unsigned short QDCount;             //询问问题个数/客户端
		unsigned short ANCount;				 //回答问题个数/服务器
		unsigned short NSCount;						//权威名称服务器计数
		unsigned short NACount;                        //附加资源计数(权威服务器对应ip数)
	};
	struct DNSRequestModule
	{
		std::string nameBuff_;
		/*一般格式 (RFC1035 4.1.2)
				标签内容长度(1个字节) + 标签内容，以标签内容长度0作为Name的结束符，例如：
				03www05pivix03net00字母个数
		  消息压缩格式 (RFC1035 4.1.4)
				如果标签内容长度的二进制前两位是11，则表示消息压缩。(只内容嵌入俩个字节，要找偏移，偏移开始到结束00)
				此时，标签内容长度1个字节+后面的1个字节一共16位，后14位表示相对DNS包起始地址的偏移(Byte)，例如：
				03www05pivix(0x)c1f3此时c0是11开头末尾压缩在距离报文头1f3处..........  .net00，00结尾
				RFC1035中规定，支持的消息压缩规则为：
				①以内容长度0结尾的标签序列
				②偏移指针
				③标签序列+偏移指针
				也就是说，Name的消息压缩要求偏移指针必须在Name的尾部，且不支持同一级存在多个偏移指针(偏移指针序列)，
				但Name的消息压缩支持嵌套的偏移指针，即指针指向的偏移位置仍然是以偏移指针结尾的数据
		*/
		unsigned short type_;     //TYPE=1表示主机IP地址、TYPE=5表示CNAME
		unsigned short class_;    //一般情况下CLASS=1表示Internet 
	};
	struct DNSResponedAnswerModule
	{
		std::string nameBuff_;
		unsigned short type_;     //TYPE=1表示主机IP地址、TYPE=5表示CNAME
		unsigned short class_;    //一般情况下CLASS=1表示Internet 
		int TTL_;        //生存时间
		unsigned short DataLength_;//Data字节数
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
	void CreatPackage(std::string& package, std::string& name);	//现只提供一个域名查询
	DNS_Request_Protocol::DNSRequestHeader GetHeader(std::string& recvBuff);
	DNS_Request_Protocol::DNSRequestModule  GetRequest(std::string& recvBuff);  //无实际意义
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


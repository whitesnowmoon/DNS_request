#include "DNS_Analysis.h"

DNS_Analysis::DNS_Analysis(std::string dnsSeverIP):
	wVersionRequested(MAKEWORD(2,2)), 
	valid(false),
	sockaddr_in_Len(sizeof(sockaddr_in)),
	dnsSeverAddr({0}),
	dnsSever(INVALID_SOCKET){
	if (WSAStartup(this->wVersionRequested, &(this->wsaData)) != 0) {
		std::cout << "winsock.dll can not open!\n";
		return;
	}
	this->dnsSever = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (INVALID_SOCKET == this->dnsSever){
		std::cout << "DNS socket can not open!\n";
		return;
	}
	dnsSeverAddr.sin_family = AF_INET;
	dnsSeverAddr.sin_port = htons(_DNS_SEVER_PORT_);
	dnsSeverAddr.sin_addr.s_addr = inet_addr(dnsSeverIP.c_str());
	valid=true;
}

void DNS_Analysis::CreatPackage(std::string& package, std::string& name) {
	DNS_Request_Protocol::DNSRequestHeader header = {0};
	DNS_Request_Protocol::DNSRequestModule request;

	header.transationID = ntohs(0x6666);
	header.flag = ntohs(0x0100);
	header.QDCount = ntohs(0x0001);
	request.nameBuff_ = regularName(name);
	request.type_ = ntohs(0x0001);
	request.class_ = ntohs(0x0001);
	package.append((char*)&header, sizeof(header));
	package.append(request.nameBuff_.c_str(), request.nameBuff_.size());
	package.append((char*)&request.type_, sizeof(request.type_));
	package.append((char*)&request.class_, sizeof(request.class_));
	this->package_size = package.size();
}

DNS_Request_Protocol::DNSRequestHeader DNS_Analysis::GetHeader(std::string& recvBuff) {
	DNS_Request_Protocol::DNSRequestHeader header;
	memcpy((char*)&header, recvBuff.c_str(),sizeof(header));
	header.transationID = ntohs(header.transationID);
	header.flag = ntohs(header.flag);
	header.QDCount = ntohs(header.QDCount);
	header.NACount = ntohs(header.NACount);
	header.NSCount = ntohs(header.NSCount);
	header.ANCount = ntohs(header.ANCount);
	return header;
}

DNS_Request_Protocol::DNSRequestModule DNS_Analysis::GetRequest(std::string& recvBuff) {
	return DNS_Request_Protocol::DNSRequestModule();
}

std::vector<DNS_Request_Protocol::DNSResponedAnswerModule> DNS_Analysis::GetAnswerModule(std::string& recvBuff,int num) {
	std::vector<DNS_Request_Protocol::DNSResponedAnswerModule> Modules;
	DNS_Request_Protocol::DNSResponedAnswerModule module;
	int Len = sizeof(unsigned short) * 3 + sizeof(int);

	auto pos=recvBuff.begin();
	pos+=package_size;
	for (size_t i = 0; i < num; i++)
	{
		module.nameBuff_ = GetName(pos, recvBuff);
		poscopy(pos, (char*)&module.type_, Len);
		module.type_ = ntohs(module.type_);
		module.TTL_ = ntohl(module.TTL_);
		module.DataLength_ = ntohs(module.DataLength_);
		module.class_ = ntohs(module.class_);
		pos += Len;
		if (module.DataLength_ != 4) {
			module.Data_ = GetName(pos,recvBuff);
		}
		else
		{
			unsigned char ip[4];
			poscopy(pos, (char*)ip, module.DataLength_);
			for (size_t i = 0; i < 4; i++)
			{
				module.Data_.append(std::to_string(ip[i]));
				module.Data_.push_back('.');
			}
			module.Data_.pop_back();
			pos += module.DataLength_;
		}
		Modules.push_back(module);
		module.Data_.clear();
		module.class_ = 0;
		module.DataLength_ = 0;
		module.TTL_ = 0;
		module.type_ = 0;
		module.nameBuff_.clear();
	}
	return Modules;
}

inline bool DNS_Analysis::is_cutdown(DNS_Request_Protocol::DNSRequestHeader header) {
	return false;
}

inline std::string DNS_Analysis::regularName(std::string& oldname) {
	std::string newName;
	char c = 0; int waitfill = 0; size_t pos;

	newName.push_back(c);
	for (pos = 0; pos < oldname.size(); pos++)
	{
		if (oldname[pos] == '.') {
			c = pos - waitfill;
			newName[waitfill] = c;
			waitfill = newName.size();
			newName.push_back(c);
		}
		else {
			c = oldname[pos];
			newName.push_back(c);
		}
	}
	c = pos - waitfill;
	newName[waitfill] = c;
	c = 0;
	newName.push_back(c);
	return newName;
}

inline bool DNS_Analysis::is_zip(std::string::iterator& pos, std::string& recvBuff, unsigned char& c) {
	if (((*pos) & 0b11000000) == 0b11000000) {
		unsigned short offset;
		auto newpos = recvBuff.begin();
		offset = ((*pos) & 0b00111111);
		offset = (offset << 8);
		offset += (unsigned char)*(++pos);
		newpos += offset;
		pos = newpos;
		c = *pos;
		return true;
	}
	return false;
}
inline void DNS_Analysis::poscopy(std::string::iterator pos, char* position,int Len) {
	char* p = position;
	for (size_t i = 0; i < Len; i++)
	{
		p[i] = *pos++;
	}
}

std::string DNS_Analysis::GetName(std::string::iterator& pos, std::string& recvBuff) {
	std::string name; std::string::iterator oldpos = pos;bool rt=false;
	unsigned char c = *pos;

	while (c!=0)
	{
		if(!rt)
			rt = is_zip(pos, recvBuff, c);
		pos++;
		for (size_t i = 0; i < c; i++)
		{
			name.push_back(*pos);
			pos++;
		}
		name.push_back('.');
		c = *pos;
	}
	name.pop_back();
	pos++;
	if (rt) {
		pos = oldpos;
		pos += 2;
	}
	return name;
}


std::vector<std::string> DNS_Analysis::DNS_Request(std::string name) {

	std::vector<std::string> IP_Addrs;
	std::vector<DNS_Request_Protocol::DNSResponedAnswerModule> Answers;
	char recvBuff[_MAX_RECV_PACKAGE_SIZE_]; int recvsum=-1;
	DNS_Request_Protocol::DNSRequestHeader header;
	std::string package;
	std::string recvstring;

	if (!valid)return IP_Addrs;
	CreatPackage(package, name);
	if (sendto(this->dnsSever, package.c_str(), package.size(), 0, (SOCKADDR*)&(this->dnsSeverAddr), this->sockaddr_in_Len) != SOCKET_ERROR) {
		while (true)
		{
			recvsum = recvfrom(this->dnsSever, recvBuff, _MAX_RECV_PACKAGE_SIZE_, 0, NULL, NULL);
			if (recvsum > 0) {
				recvstring.append(recvBuff, recvsum);
				header =GetHeader(recvstring);
				GetRequest(recvstring);
				this->AnswerModules=Answers = GetAnswerModule(recvstring,header.ANCount);
				break;
			}
		}
	}
	else{

	}
	for (auto pos = Answers.begin(); pos!= Answers.end(); pos++)
	{
		IP_Addrs.emplace_back(pos->Data_);
	}
	return IP_Addrs;
}

void DNS_Analysis::printimformation() {
	for (auto i : this->AnswerModules) {
		std::cout<<"name:"<< i.nameBuff_ << "\nip/nextDomain:" << i.Data_ << "\nDataLength:" << i.DataLength_ << "\nTime:" << i.TTL_ << "\nrequestType:" << i.type_ << "\n\n";
	}
}

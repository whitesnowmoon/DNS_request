#include<iostream>
#include"DNS_Analysis.h"
int main() {

	DNS_Analysis dns("8.8.8.8");
	dns.DNS_Request("www.pivix.net");
	dns.printimformation();
	return 0;
}

#ifndef PROTECT_HOOK_IOS_H
#define PROTECT_HOOK_IOS_H

int protect_hook_install(int tcp_port, int udp_port);
void protect_hook_rescan(void);
void protect_hook_uninstall(void);

int goInterceptTCP(char *ip, int port);
int goInterceptUDP(char *ip, int port);
void goRegisterTCP(int localPort, char *ip, int port);
int goLookupTCP(int localPort, char *ipBuf, int ipLen, int *port);
void goRegisterUDP(int localPort, char *ip, int port);
int goLookupUDP(int localPort, char *ipBuf, int ipLen, int *port);
void goUnregisterPort(int localPort);

#endif

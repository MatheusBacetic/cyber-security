#include "nftables.h"

#include <stdio.h>
#include <stdlib.h>

void block_ip(const char *ip){
	char command[256];

	snprintf(
		command,
		sizeof(command),
		"sudo nft add rule inet firewall blacklist ip saddr %s drop",
		ip
	);

	printf("[NFTABLES] Bloqueando IP: %s\n", ip);

	int result = system(command);

	if (result != 0) {
		printf("[NFTABLES ERROR] Falha ao bloquear IP: %s\n", ip);
	}	
}

#include "server.h"
#include "logger.h"
#include "ids.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

void start_server(int port) {

	int server_fd;
	int client_fd;

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);

	server_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (server_fd < 0) {
		perror("Erro ao criar socket");
		exit(1);
	}

	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);

	if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Erro no bind");
		close(server_fd);
		exit(1);
	}

	if (listen(server_fd,10) < 0) {
		perror("Erro no listen");
		close(server_fd);
		exit(1);
	}

	printf("[+] Honeypot SSH escutando na porta %d...\n", port);

	while (1) {

		client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

		if (client_fd < 0) {
			perror("Erro no accept");
			continue;
		}
		
		printf("[CONEXAO] IP: %s\n", inet_ntoa(client_addr.sin_addr));
		
		log_connection(inet_ntoa(client_addr.sin_addr));
		
		analyze_connection(inet_ntoa(client_addr.sin_addr));
		
		char *banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n";
		write(client_fd, banner, strlen(banner));

		close(client_fd);
	}

	close(server_fd);
}

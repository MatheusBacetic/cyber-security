#include "logger.h"

#include <stdio.h>
#include <time.h>

void log_connection(const char *ip) {

	FILE *log_file;

	time_t now;
	
	struct tm *time_info;

	now = time(NULL);
	time_info = localtime(&now);
	
	log_file = fopen("logs/connections.log","a");

	if (log_file ==  NULL) {
		perror("Erro ao abrir arquivo de log");
		return;
	}

	fprintf(
		log_file,
		 "[%04d-%02d-%02d %02d:%02d:%02d] IP: %s\n",
        	time_info->tm_year + 1900,
        	time_info->tm_mon + 1,
        	time_info->tm_mday,
        	time_info->tm_hour,
        	time_info->tm_min,
        	time_info->tm_sec,
      	  	ip
    	);

	fclose(log_file);
}

void log_alert(const char *ip, int attempts, const char *type) {

	FILE *log_file;
	
	time_t now;
	struct tm *time_info;
	
	now = time(NULL);
	time_info = localtime(&now);

	log_file = fopen("logs/alerts.log", "a");

	if( log_file == NULL) {
		perror("Erro ao abrir arquivo de alertas");
		return;
	}

	fprintf(
		log_file,
	        "[%04d-%02d-%02d %02d:%02d:%02d] [IDS ALERT] IP: %s | Tentativas: %d | Tipo: %s\n",
	        time_info->tm_year + 1900,
	        time_info->tm_mon + 1,
	        time_info->tm_mday,
	        time_info->tm_hour,
	        time_info->tm_min,
        	time_info->tm_sec,
        	ip,
        	attempts,
        	type
   	 );

    	fclose(log_file);
}

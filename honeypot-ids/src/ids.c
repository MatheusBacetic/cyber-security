#include "ids.h"
#include "logger.h"
#include "nftables.h"

#include <stdio.h>
#include <string.h>

#define MAX_IPS 100
#define ALERT_THRESHOLD 5

typedef struct {
	char ip[46];
	int attempts;
	int alerted;
}IpTracker;

static IpTracker trackers[MAX_IPS];
static int tracker_count = 0;

void analyze_connection(const char *ip){
	for(int i =0; i < tracker_count; i++){
		if(strcmp(trackers[i].ip, ip) == 0) {
			trackers[i].attempts++;
	
			if(trackers[i].attempts >= ALERT_THRESHOLD && trackers[i].alerted == 0) {
				printf("[IDS ALERT] Possível brute force detectado: %s (%d tentativas)\n",
                       			ip,
                       			trackers[i].attempts);
				log_alert(ip, trackers[i].attempts, "brute_force");
			
				if(strcmp(ip,"127.0.0.1") != 0){
					block_ip(ip);
				}

				trackers[i].alerted = 1;
			}

			return;

		}

	}

	if(tracker_count < MAX_IPS){
		strcpy(trackers[tracker_count].ip,ip);
		trackers[tracker_count].attempts = 1;
		tracker_count++;
	}
}


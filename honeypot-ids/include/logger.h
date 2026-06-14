#ifndef LOGGER_H
#define LOGGER_H

void log_connection(const char *ip);
void log_alert(const char *ip, int attempts, const char *type);

#endif

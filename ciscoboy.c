/*
 ============================================================================
 Name        : ciscoboy.c
 Author      : Trauma
 Version     :
 Copyright   : 
 Description : Cisco 79XX telephone remote control lib
 ============================================================================
 */

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#define BUF_SIZE 512

#define DEFAULT_PORT 23
#define TRUE 1;
#define FALSE 0;

typedef struct phone{
	int phone_sock;
	unsigned short test_active;
} phone;

void die(char *mess) {
	perror(mess);
	exit(1);
}

void usage(char *prog_name){
	printf("Usage: %s -i <phone_ip> -p <phone_password>\n",prog_name);
	exit(1);
}

int send_to_phone(const phone *p, char* buf){
	int sent = 0;
	char cmd[strlen(buf)+2];

	sprintf(cmd,"%s\r\n",buf);

	if((sent = send(p->phone_sock,cmd,strlen(cmd),0)) < 0)
		perror("Failed to sent bytes to phone");

	return sent;
}

int read_from_phone(const phone *p,char* buf, const unsigned int buf_len){
	int recvd = 0;

	if((recvd = recv(p->phone_sock, buf, buf_len-1, 0))<0)
		perror("Failed to receive bytes from phone");

	buf[recvd] = '\0';

	return recvd;
}

int connect_to_phone(phone *p,const char *phone_addr,const int port,char *pass){
	struct sockaddr_in remote;
	int sock;
	char buf[BUF_SIZE];
	int bytes;
	unsigned int total;
	
	/*See telnet protocol RFC*/
	char negotiation_1[] = {0xFF,0xFC,0X18,0xFF,0xFC,0x20,0xFF,0xFC,0x23,0xFF,0xFC,0x27,0xFF,0xFD,0x03};
	char negotiation_2[] = {0xFF,0xFC,0x01,0xFF,0xFC,0x1F,0xFF,0xFE,0x05,0xFF,0xFB,0x21};
	
	if((sock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
		return -1;
	
	memset(&remote,0,sizeof(struct sockaddr_in));

	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(phone_addr);
	remote.sin_port = htons(port);

	/*Open connection*/
	if(connect(sock,(struct sockaddr *)&remote,sizeof(remote)) < 0 ||
			send(sock,negotiation_1,15,0) < 0 ||
			send(sock,negotiation_2,12,0) < 0 ){
	        close(sock);
		return -1;
	}

	/*Wait until the password prompt appears*/
	total = 0;
	do{

		if((bytes = recv(sock,buf+total,BUF_SIZE-1,0)) < 0)
			return -1;

		buf[total = (total+bytes) % BUF_SIZE] = '\0';

	}while(bytes > 0 && strstr(buf,"Password:") );

	p->phone_sock = sock;
	p->test_active = FALSE;

	/*Send password to phone*/
	if(send_to_phone(p,pass) < 0){
		close(sock);
		return -1;
	}

	return 0;
}

int open_test_session(phone *p){

	if(!p->test_active){
		if(send_to_phone(p,"test open") < 0)
			return -1;

		p->test_active = TRUE;
	}

	return 0;
}

int close_test_session(phone *p){

	if(p->test_active){
		if(send_to_phone(p,"test close") < 0)
			return -1;

		p->test_active = FALSE;
	}

	return 0;
}

int release_phone(phone *p){
	/*Close test session*/
	if(p->test_active)
		close_test_session(p);

	/*Close telnet session*/
	if(send_to_phone(p,"exit") < 0)
		perror("Failed to release command to phone");

	return close(p->phone_sock);
}

int dial(phone *p, char *num){
	char cmd[BUF_SIZE];

	if(!p->test_active && open_test_session(p) < 0)
		return -1;

	sprintf(cmd,"test key %s",num);
	if(send_to_phone(p,cmd) < 0)
		return -1;

	return 0;
}

int log_phone(const phone *p){
	int recvd;
	char buf[BUF_SIZE];

	while((recvd = read_from_phone(p,buf,BUF_SIZE)) > 0)
	  printf("%s",buf);

	perror("Connection lost");

	return recvd;
}

int getargs(char **ip, char **pass, int argc, char **argv){
	int c;

	while ((c = getopt (argc, argv, "i:p:")) != -1)
		switch (c){
		case 'i':
			*ip = optarg;
			break;
		case 'p':
			*pass = optarg;
			break;
		case '?':
			if (optopt == 'i' || optopt == 'p')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			return -1;
		default:
			usage(argv[0]);
		}

	return (pass != NULL && ip != NULL) ? 0 : -1;
}

int wait_for_input(phone *p){
	char buf[BUF_SIZE];
	int cmp;
	do{
	  fgets(buf,BUF_SIZE,stdin);
	  buf[strlen(buf)-1] = '\0';

	  if((cmp = strcmp("quit",buf)) != 0 &&  dial(p,buf) < 0)
	    return -1;
	  
	}while(cmp != 0);

	return 0;
}

int main(int argc, char *argv[]) {
	phone p;
	char *pass = NULL;
	char *ip = NULL;
	int pid;
	
	if( getargs(&ip,&pass,argc,argv) < 0 )
		usage(argv[0]);

	if( connect_to_phone(&p,ip,DEFAULT_PORT,pass) < 0 )
		die("Failed to open connection");

	if((pid = fork()) == 0){
	  log_phone(&p);
	  exit(EXIT_FAILURE);
	}

	if(wait_for_input(&p) < 0)
	  perror("Something failed");

	if(release_phone(&p) < 0)
		die("Failed to close connection");

	printf("Bye bye\n");

	return EXIT_SUCCESS;
}

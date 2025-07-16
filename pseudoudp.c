/*
 * 自前で疑似UDPパケットを生成して送信する。
 * なおlibpcapで送信するのでそれなりの権限が必要。
 * Copyright (c) 2025 nuel-ch
 */

#include <pcap/pcap.h>
#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// パケットを送信するインタフェース名
#define SEND_IF "ens192"

// 発IPアドレス、発ポート、発MACアドレス
#define SRC_IP  "192.168.100.32"
#define SRC_PORT 12345
#define SRC_MAC {0x00,0x0c,0x29,0xea,0x68,0x96}
//#define SRC_MAC {0x00,0x00,0x00,0x00,0x00,0x00}

// 宛先IPアドレス、宛先ポート、宛先MACアドレス
// GWを越える通信のときはGWのMACアドレスを宛先MACアドレスに設定する
#define DEST_IP "192.168.100.135"
#define DEST_PORT 44444
#define DEST_MAC {0x00,0x0c,0x29,0x81,0x4d,0xe9}
//#define DEST_MAC {0xff,0xff,0xff,0xff,0xff,0xff}


#pragma pack(1) //構造体をパディングなしできっちりパッキング
struct {
	struct {
		uint8_t  dest_mac[6];
		uint8_t  src_mac[6];
		uint16_t type;
	} ether;

	struct {
		uint8_t  ver_hlen; // 0x45固定
		uint8_t  service_type; //0xx固定
		uint16_t total_length; //IPヘッダを含むパケットのサイズ
		uint16_t id; //パケット識別のID。分割パケットは同じIDを持つ
		uint16_t flag_fragment; //0x40 0x00固定
		uint8_t  ttl;  //TTL 最大値0xff固定でいいかも。
		uint8_t  protocol_number; // ICMP=1 TCP=6 UDP=17
		uint16_t checksum; //ヘッダチェックサム
		uint32_t src_ip; // 発IP
		uint32_t dest_ip; //着IP
	} ip;
	struct {
		uint16_t src_port;
		uint16_t dest_port;
		uint16_t length; // UDPヘッダ＋ペイロードのサイズ
		uint16_t checksum; //HDPヘッダ+ペイロードのチェックサム

	} udp;
	char data[1500]; //データ本体
} packet;


/* -------- チェックサム計算関数 ------------ */
static uint32_t sum=0;

void checksum_init(){
	sum=0;
}

void checksum_add(uint8_t hi, uint8_t low){
	sum += ((hi<<8) | low);
	if(sum>0x0000ffff){
		sum = sum & 0x0000ffff;
		sum++;
	}
}

unsigned short checksum_result(){
	return (~sum) & 0x0000ffff;
}
/* ------------------------------------------ */

uint32_t main(uint32_t argc, char *argv[]){

	uint8_t msg[]="123456\n";
	uint16_t msg_size=strlen(msg);
	memset(&packet.data,1500,0);
	memcpy(packet.data, msg, strlen(msg));

	//Etherヘッダ
	//発と宛先のMACアドレスを設定
	uint8_t src_mac[]=SRC_MAC;
	uint8_t dest_mac[]=DEST_MAC;
	memcpy(&packet.ether.src_mac, src_mac, 6);
	memcpy(&packet.ether.dest_mac, dest_mac, 6);
	//タイプはIP
	packet.ether.type=htons(0x0800);

	//IPヘッダ
	packet.ip.ver_hlen=0x45;
	packet.ip.service_type=0x00;
	packet.ip.total_length=htons(sizeof(packet.ip)+sizeof(packet.udp)+msg_size);//IPヘッダ+UDPヘッダ+データの合計
	packet.ip.id=htons(0x4445); //IDは毎回同じ値にならないように乱数値にする
	packet.ip.flag_fragment=htons(0x4000);
	packet.ip.ttl=0xff; // TTLは最大値を入れておく
	packet.ip.protocol_number=0x11; // ICMP=0x01 TCP=0x06 UDP=0x11
	packet.ip.checksum=0; //後の計算用に0クリアしておく
	//発と着のIPアドレスを設定
	struct hostent *host;
	host=gethostbyname(SRC_IP);
	memcpy(&packet.ip.src_ip,  host->h_addr_list[0], 4);
	host=gethostbyname(DEST_IP);
	memcpy(&packet.ip.dest_ip, host->h_addr_list[0], 4);

	//UDPヘッダ
	packet.udp.src_port=htons(SRC_PORT);
	packet.udp.dest_port=htons(DEST_PORT);
	packet.udp.length=htons(sizeof(packet.udp)+msg_size);
	packet.udp.checksum=0; //後の計算用に0クリアしておく

	//IPヘッダのチェックサム計算
	{
		checksum_init();
		uint8_t *ptr=(uint8_t *)&packet.ip;
		for(uint8_t i=0; i< sizeof(packet.ip)/2; i++){
			checksum_add(ptr[i*2],ptr[i*2+1]);
		}
		packet.ip.checksum=htons(checksum_result());
	}

	//UDPパケットのチェックサム計算
	checksum_init();
	//ここから擬似ヘッダ
	{
		uint8_t *ptr;
	//発IP
		ptr=(uint8_t *)&packet.ip.src_ip;
		checksum_add(ptr[0],ptr[1]); checksum_add(ptr[2],ptr[3]);
	//着IP
		ptr=(uint8_t *)&packet.ip.dest_ip;
		checksum_add(ptr[0],ptr[1]); checksum_add(ptr[2],ptr[3]);
	//パティング(0x00)＋プロトコル番号
		checksum_add(0x00, packet.ip.protocol_number);
	//UDPパケット長
		ptr=(uint8_t *)&packet.udp.length;
		checksum_add(ptr[0],ptr[1]);
	}
	//UDPパケットヘッダ＋データ本体
	{
		uint8_t *ptr=(uint8_t *)&packet.udp;
		for(uint32_t i=0; i< (sizeof(packet.udp)+msg_size+1)/2 ; i++){
			checksum_add(ptr[i*2], ptr[i*2+1]);
		}
		packet.udp.checksum=htons(checksum_result());
	}

	//送信パケットデータを16進ダンプ
	{
		uint8_t *p=(uint8_t *)&packet;
		for(int i=0; i<sizeof(packet.ether)+sizeof(packet.ip)+sizeof(packet.udp)+msg_size; i++){
			printf("%02x ",p[i]);
			if(i%16==15) printf("\n");
		}
		printf("\n");
	}

	//作成したパケット送信
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *cap;
	int result;

	//pcapライブラリ初期化
	result=pcap_init(PCAP_CHAR_ENC_LOCAL, pcap_errbuf);
	printf("pcap_init() %d\n",result);

	//送信するポートオープン
	cap = pcap_create(SEND_IF, pcap_errbuf);
	if(cap==NULL){
		printf("pcap_create() %s\n", pcap_errbuf);
	}

/*
	//透過モードON
	result=pcap_set_promisc(cap, 1);
	printf("pcap_set_promisc() %d\n", result);
*/

	//fdを有効化
	result=pcap_activate(cap);
	printf("pcap_activate() %d\n", result);

	//パケット送信
	uint16_t size=sizeof(packet.ether)+sizeof(packet.ip)+sizeof(packet.udp)+msg_size;
	pcap_inject(cap, (char *)&packet, size);

	//ポートクローズ
	pcap_close(cap);

	return 0;
}


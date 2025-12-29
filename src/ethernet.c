#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    //step1:数据长度检查
    if(buf->len < 14) {
        return;
    }
    //step2:移除包头
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    buf_remove_header(buf, 14);
    //step3:向上传递数据包
    // 注意：协议类型需要转换为大端序，所以使用swap16
    net_in(buf, swap16(hdr->protocol16), hdr->src);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // Step1: 数据长度检查与填充
    if(buf->len <ETHERNET_MIN_TRANSPORT_UNIT) {
        int padding_len = ETHERNET_MIN_TRANSPORT_UNIT - buf->len;
        buf_add_padding(buf, padding_len);
    }
    //step2:添加包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    //step3:添加目的mac
    for(int i = 0; i < NET_MAC_LEN; i++) {
        hdr->dst[i] = mac[i];
    }
    //step4:添加源mac
    uint8_t src_mac[] = NET_IF_MAC;
    memcpy(hdr->src, src_mac, NET_MAC_LEN);
    //step5:填写协议类型（转化成大端序）
    hdr->protocol16 = swap16(protocol);
    //step6:发送数据帧
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
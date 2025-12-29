#include "udp.h"
#include "icmp.h"
#include "ip.h"
#include <string.h>

/**
 * @brief udp处理程序表
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1: 包检查
    if (buf->len < sizeof(udp_hdr_t)) 
        return;

    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    uint16_t udp_len = swap16(hdr->total_len16);
    
    if (buf->len < udp_len) 
        return;

    // Step2: 重新计算校验和
    uint16_t checksum_backup = hdr->checksum16;
    hdr->checksum16 = 0;
    uint16_t calc_checksum = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip);
    
    if (calc_checksum != checksum_backup) 
        return;
    hdr->checksum16 = checksum_backup;

    // Step3: 查询处理函数
    uint16_t dst_port = swap16(hdr->dst_port16);
    udp_handler_t *handler = map_get(&udp_table, &dst_port);

    if (handler == NULL) {
        // Step4: 端口不可达，发送ICMP差错报文
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
    } else {
        // Step5: 找到处理函数，去除UDP头部并调用
        uint16_t src_port = swap16(hdr->src_port16);
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, src_port);
    }
}

/**
 * @brief 处理一个要发送的数据包
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // Step1: 添加UDP头部
    buf_add_header(buf, sizeof(udp_hdr_t));

    // Step2: 填充UDP头部字段
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    hdr->src_port16 = swap16(src_port);
    hdr->dst_port16 = swap16(dst_port);
    hdr->total_len16 = swap16(buf->len);

    // Step3: 计算校验和
    hdr->checksum16 = 0;
    hdr->checksum16 = transport_checksum(NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);

    // Step4: 调用IP层发送
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}
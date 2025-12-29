
#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // Step1: 初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    
    // Step2: 填写ARP报头
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    
    // Step3: 设置操作类型和目标IP地址
    // 注意：操作类型需要从主机字节序转换为网络字节序
    pkt->opcode16 = swap16(ARP_REQUEST);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    
    // Step4: 发送ARP请求（使用广播地址）
    // ARP请求是广播报文，目标MAC地址为全FF
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // Step1: 初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    
    // Step2: 填写ARP报头
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    
    // Step3: 设置操作类型、目标IP地址和目标MAC地址
    // 注意：操作类型需要从主机字节序转换为网络字节序
    pkt->opcode16 = swap16(ARP_REPLY);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);
    
    // Step4: 发送ARP响应（直接发送给请求者）
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // Step1: 检查数据包长度
    if (buf->len < sizeof(arp_pkt_t)) {
        return; // 数据包不完整，丢弃
    }
    
    // Step2: 报头检查
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    
    // 检查硬件类型（以太网）
    if (swap16(arp_pkt->hw_type16) != ARP_HW_ETHER) {
        return;
    }
    
    // 检查上层协议类型（IP）
    if (swap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP) {
        return;
    }
    
    // 检查硬件地址长度
    if (arp_pkt->hw_len != NET_MAC_LEN) {
        return;
    }
    
    // 检查协议地址长度
    if (arp_pkt->pro_len != NET_IP_LEN) {
        return;
    }
    
    // 检查操作类型（ARP_REQUEST或ARP_REPLY）
    uint16_t opcode = swap16(arp_pkt->opcode16);
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        return;
    }
    
    // Step3: 更新ARP表项
    // 将发送方的IP-MAC映射存入ARP表
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
    
    // Step4: 查看缓存情况
    // 检查是否有等待该IP地址MAC地址的数据包
    buf_t *cached_buf = (buf_t *)map_get(&arp_buf, arp_pkt->sender_ip);
    
    if (cached_buf != NULL) {
        // 有缓存的数据包，说明之前因为不知道MAC地址而无法发送
        // 现在知道了MAC地址，可以发送缓存的数据包了
        ethernet_out(cached_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        
        // 发送后删除缓存
        map_delete(&arp_buf, arp_pkt->sender_ip);
    } else {
        // 没有缓存，检查是否是ARP请求且目标IP是本机
        if (opcode == ARP_REQUEST) {
            // 检查目标IP是否为本机IP
            if (memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
                // 是本机，发送ARP响应
                arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
            }
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // Step1: 查找ARP表
    uint8_t *mac = (uint8_t *)map_get(&arp_table, ip);
    
    if (mac != NULL) {
        // Step2: 找到对应MAC地址，直接发送
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } else {
        // Step3: 未找到对应MAC地址
        // 检查是否已经有等待该IP的缓存包
        buf_t *cached_buf = (buf_t *)map_get(&arp_buf, ip);
        
        if (cached_buf != NULL) {
            // 已经有缓存包，说明正在等待ARP响应，不再发送ARP请求
            return;
        } else {
            // 没有缓存包，缓存当前数据包并发送ARP请求
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}

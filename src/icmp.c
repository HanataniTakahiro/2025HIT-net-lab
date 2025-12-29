#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送ICMP响应报文
 *
 * @param req_buf 收到的ICMP请求包
 * @param src_ip 源IP地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // Step1: 初始化并封装数据
    buf_t txbuf;
    buf_init(&txbuf, req_buf->len);  // 创建与请求相同大小的缓冲区
    memcpy(txbuf.data, req_buf->data, req_buf->len);  // 复制请求数据
    
    // Step2: 修改头部字段
    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr_t *req_hdr = (icmp_hdr_t *)req_buf->data;
    
    hdr->type = ICMP_TYPE_ECHO_REPLY;  // 修改为回显应答
    hdr->code = 0;                     // 代码为0
    hdr->id16 = req_hdr->id16;         // 保持标识符不变
    hdr->seq16 = req_hdr->seq16;       // 保持序列号不变
    
    // Step3: 填写校验和
    hdr->checksum16 = 0;  // 先将校验和字段置0
    hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    
    // Step4: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    //step1：报头检测
    if (buf->len < sizeof(icmp_hdr_t)) {
        //若长度小于icmp首部长度，丢弃
        return;
    }
    //step2：检查ICMP类型，如果是请求就发送应答
    icmp_hdr_t *hdr = (icmp_hdr_t*)buf->data;
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        icmp_resp(buf, src_ip);
    }
}
/**
 * @brief 发送ICMP不可达报文
 *
 * @param recv_buf 收到的IP数据包
 * @param src_ip 源IP地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // Step1: 初始化并填写报头
    int total_size = sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8;
    buf_t txbuf;
    buf_init(&txbuf, total_size);
    
    // 填充ICMP头部
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;  // 类型为不可达
    icmp_hdr->code = code;               // 根据参数设置代码
    icmp_hdr->id16 = 0;                  // 标识符为0
    icmp_hdr->seq16 = 0;                 // 序列号为0
    
    // Step2: 填写数据与校验和
    // 填写IP数据报首部
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(icmp_hdr + 1);
    ip_hdr_t *recv_ip_hdr = (ip_hdr_t *)recv_buf->data;
    memcpy(ip_hdr, recv_ip_hdr, sizeof(ip_hdr_t));
    
    // 填写IP数据报的前8个字节数据字段
    uint8_t *data = (uint8_t *)(ip_hdr + 1);
    uint8_t *recv_ip_data = (uint8_t *)(recv_ip_hdr + 1);
    memcpy(data, recv_ip_data, 8);
    
    // 计算校验和
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, total_size);
    
    // Step3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}
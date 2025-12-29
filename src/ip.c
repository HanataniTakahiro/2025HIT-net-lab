#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    ip_hdr_t *hdr = (ip_hdr_t*)buf->data;
    uint16_t total_len = swap16(hdr->total_len16);
    uint16_t ogn_checksum = hdr->hdr_checksum16;//将原来的校验和保存起来
    size_t hdr_len = hdr->hdr_len * 4;//计算头部长度（以字节为单位）
    //step1：检查数据包长度
    if (buf->len < sizeof(ip_hdr_t)) {
        return;//小于ip头部长度直接丢弃
    }

    //step2:进行报头检测
    //检查版本号
    if (hdr->version != IP_VERSION_4) {
        return;//版本号不为4直接丢弃
    }
    //检查总长度
    if (total_len > buf->len) {
        return;//总长度字段大于收到的数据包长度，直接丢弃
    }
    //step3：校验头部校验和
    hdr->hdr_checksum16 = 0;//将校验和字段设为0
    uint16_t new_checksum = checksum16((uint16_t*)hdr, hdr_len);//计算校验和
    if (new_checksum != ogn_checksum) {
        return;//如果计算得到的校验和与原来的校验和不相等，那么丢弃
    } else {
        hdr->hdr_checksum16 = ogn_checksum;
    }
    //step4：对比目的ip地址
    if (memcmp(net_if_ip, hdr->dst_ip, NET_IP_LEN) != 0) {
        return;//如果目的ip不是本机ip，将数据包丢弃
    }
    //step5:去除填充字段
    if (total_len < buf->len) {
        buf_remove_padding(buf, buf->len - total_len);//去除填充字段
    }
    //step6：去掉ip报头
    // ip_hdr_t *ogn_hdr;
    // memcpy(ogn_hdr, hdr, hdr_len);//把ip头拷贝下来，恢复时使用
    buf_remove_header(buf, hdr_len);
    //step7：向上传递数据包
    int message = net_in(buf, hdr->protocol, hdr->src_ip);
    if (message == -1) {
        buf_add_header(buf, hdr_len);
        memcpy(buf->data, hdr, hdr_len);//如果返回不可达信息，重新添加ip报头
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    //step1：增加头部
    buf_add_header(buf, sizeof(ip_hdr_t));

    //step2：填写头部字段
    ip_hdr_t *hdr = (ip_hdr_t*)buf->data;
    hdr->hdr_len = 5;//填写首部长度
    hdr->version = IP_VERSION_4;//填写版本号
    hdr->tos = 0;//填写服务类型
    hdr->total_len16 = swap16(buf->len);//填写总长度字段
    hdr->id16 = swap16(id);//填写标识字段
    hdr->flags_fragment16 = 0;//填写标志和片偏移字段
    if (mf) {
        //如果mf有效，填写mf标志
        hdr->flags_fragment16 |= IP_MORE_FRAGMENT;
    }
    uint16_t offset_units = offset / 8;  // 需要转换为8字节单位
    hdr->flags_fragment16 |= (offset_units & 0x1FFF);//分片偏移为该字段的后十三位
    hdr->flags_fragment16 = swap16(hdr->flags_fragment16);//别忘了字节序转换
    hdr->ttl = 64;//填写生存时间
    hdr->protocol = protocol;//填写协议
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);//填写目的IP地址
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);//填写源IP

    hdr->hdr_checksum16 = 0;//先将校验和字段清零，再计算校验和
    hdr->hdr_checksum16 = checksum16((uint16_t*)hdr, sizeof(ip_hdr_t));

    arp_out(buf, ip);//发送
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
static int packet_id = 0;//全局id，每次发送时递增
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    //step1：检查数据报包长是否大于MTU减去ip首部长度
    int id = packet_id++;//递增id

    if (buf->len > 1480) {
        //step2：如果大于最大包长，分片处理
        size_t fragments;
        if (buf->len % 1480 == 0) {
            fragments = buf->len / 1480;//计算总片数，分类讨论能不能整除
        } else {
            fragments = buf->len / 1480 + 1;
        }

        for (int i = 0; i < fragments; i++) {
            buf_t *ip_buf = (buf_t*)malloc(sizeof(buf_t));

            if (ip_buf == NULL) {
                //处理内存分配失败
                return;
            }

            size_t fragments_offset = i * 1480;//计算每个分片的偏移量字段
            size_t fragments_len;//初始化每个分片的长度字段
            int fragments_mf;

            if (i == fragments - 1) {
                fragments_len = buf->len - fragments_offset;//计算最后一个分片的长度
                fragments_mf = 0;
            } else {
                fragments_len = 1480;//其余分片都是最大长度
                fragments_mf = 1;
            }

            buf_init(ip_buf, fragments_len);
            
            //截断原数据包对应片段到ip_buf中
            memcpy(ip_buf->data, buf->data + fragments_offset, fragments_len);
            ip_buf->len = fragments_len;

            //调用分片发送函数
            ip_fragment_out(ip_buf, ip, protocol, id, fragments_offset, fragments_mf);
        }
    } else {
        //step3：数据包长度小于最大长度，直接发送
        ip_fragment_out(buf, ip, protocol, id, 0, 0);
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"

#include "ip.h"
#include "net.h"
#include "util.h"

struct ip_hdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t total;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[];
};

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xFFFFFFFF; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex.  */
static struct ip_iface *ifaces;

int ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp                  = ep + 1;
    }

    return 0;
}

char *ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);

    return p;
}

static void ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr  = (struct ip_hdr *)data;
    v    = (hdr->vhl & 0xF0) >> 4;
    hl   = hdr->vhl & 0x0F;
    hlen = hl << 2;
    fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)\n]", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);
    fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xE000) >> 13, offset & 0x1FFF);
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    // Exercise 7-3: IPインタフェースにアドレス情報を設定
    // (1) iface->unicast: 引数unicastを文字列からバイナリ値へ変換して設定する
    //     ・変換に失敗した場合はエラーを返す (不要になったifaceのメモリ開放を忘れずに)
    if (ip_addr_pton(unicast, &iface->unicast) == -1) {
        errorf("setting IP address failure");
        memory_free(iface);
        return NULL;
    }

    // (2) iface->netmask: 引数netmaskを文字列からバイナリ値へ変換して設定する
    //     ・変換に失敗した場合はエラーを返す (不要になったifaceのメモリ開放を忘れずに)
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        errorf("setting netmask failure");
        memory_free(iface);
        return NULL;
    }

    // (3) iface->broadcast: iface->unicastとiface->netmaskの値から算出して設定する
    iface->broadcast = (iface->unicast & iface->netmask) | ~iface->netmask;

    return iface;
}

/* NOTE: must not be called after net_run() */
int ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    // Exercise 7-4: IPインタフェースの登録
    // (1) デバイスにIPインタフェース (iface) を登録する
    //     ・エラーが返されたらこの関数もエラーを返す
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }

    // (2) IPインタフェースのリスト (iface) の先頭にifaceを挿入する
    iface->next = ifaces;
    ifaces      = iface;

    infof("registered: dev=%s, unicast: %s, netmask: %s, broadcast: %s", dev->name,
          ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));

    return 0;
}

struct ip_iface *ip_iface_select(ip_addr_t addr)
{
    // Exercise 7-5: IPインタフェースの検索
    // ・インタフェースリスト (iface) を巡回
    //   ・引数addrで指定されたIPアドレスを持つインタフェースを返す
    // ・合致するインタフェースが発見できなかったらNULLを返す
    struct ip_iface *iface;

    for (iface = ifaces; iface; iface = iface->next) {
        if (iface->unicast == addr) {
            return iface;
        }
    }

    return NULL;
}

static void ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset, verified;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data;

    // Exercise 6-1: IP データグラムの検証
    // (1) バージョン
    //     IP_VERSION_IPV4 と一致しない場合はエラーメッセージを出力して中断
    v = (hdr->vhl & 0xF0) >> 4;
    if (v != IP_VERSION_IPV4) {
        errorf("detect invalid IP version: %u", v);
        return;
    }

    // (2) ヘッダ長
    //     入力データの長さ (len) がヘッダ長より小さい場合はエラーメッセージを出力して中断
    hlen = (hdr->vhl & 0x0F) << 2;
    if (len < hlen) {
        errorf("length error: input length (%u) is shorter than header length (%u)", len, hlen);
        return;
    }

    // (3) トータル長
    //     入力データの長さ (len) がトータル長より小さい場合はエラーメッセージを出力して中断
    total = hton16(hdr->total);
    if (len < total) {
        errorf("length error: input length (%u) is shorter than total length (%u)", len, total);
        return;
    }

    // (4) チェックサム
    //     cksum16() での検証に失敗した場合はエラーメッセージを出力して中断
    verified = cksum16((uint16_t *)hdr, hlen, 0);
    if (verified != 0) {
        errorf("checksum error: sum=0x%04x, verified=0x%04x", ntoh16(hdr->sum), verified);
        return;
    }

    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1FFF) {
        errorf("fragments does not support");
        return;
    }

    // Exercise 7-6: IPデータグラムのフィルタリング
    // (1) デバイスに紐づくIPインタフェースを取得
    //     ・IPインタフェースを取得できなかったら中断する
    if (!(iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IP))) {
        errorf("net_device_get_iface() failure");
        return;
    }

    // (2) 宛先IPアドレスの検証
    //     ・以下のいずれにも一致しない場合は「他ホスト宛」と判断して中断する (エラーメッセージは出力しない)
    //      a. インタフェースのユニキャストIPアドレス
    //      b. ブロードキャストIPアドレス (255.255.255.255)
    //      c. インタフェースが属するサブネットのブロードキャストIPアドレス (xxx.xxx.xxx.255など)
    if (hdr->dst != iface->unicast && hdr->dst != IP_ADDR_BROADCAST && hdr->dst != iface->broadcast) {
        return;
    }

    debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, total);
}

static int ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEEDARP) {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        } else {
            errorf("ARP hasn't been implemented");
            return -1;
        }
    }

    // Exercise 8-4: デバイスから送信
    // ・net_device_output()を呼び出してインタフェースに紐づくデバイスからIPデータグラムを送信
    // ・net_device_output()の戻り値をこの関数の戻り値として返す
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
}

static ssize_t ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr           = (struct ip_hdr *)buf;
    // Exercise 8-3: IPデータグラムの生成
    // (1) IPヘッダの各フィールドに値を設定
    //     ・IPヘッダの長さはIP_HDR_SIZE_MIN固定とする (オプションなし)
    //     ・TOS=0, TTL=255とする
    //     ・チェックサムの計算結果はバイトオーダーを変換せずにそのまま設定する (ネットワークバイトオーダーのバイト列のチェックサム計算結果はネットワークバイトオーダーで得られる)
    //       ・チェックサムの計算の際、あらかじめチェックサムフィールドに0を設定するのを忘れずに
    hdr->vhl      = (IP_VERSION_IPV4 << 4) | (IP_HDR_SIZE_MIN / 4);
    hdr->tos      = 0;
    total         = hton16(IP_HDR_SIZE_MIN + len);
    hdr->total    = total;
    hdr->id       = hton16(id);
    hdr->offset   = hton16(offset);
    hdr->ttl      = 255;
    hdr->protocol = protocol;
    hdr->sum      = 0;
    hdr->src      = src;
    hdr->dst      = dst;

    hlen     = IP_HDR_SIZE_MIN;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);

    // (2) IPヘッダの直後にデータを配置 (コピー) する
    memcpy(buf + IP_HDR_SIZE_MIN, data, len);

    debugf("dev=%s, dst=%s, protocol=%u, len=%u", NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);

    return ip_output_device(iface, buf, total, dst);
}

static uint16_t ip_generate_id(void)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id   = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;

    if (src == IP_ADDR_ANY) {
        errorf("IP routing hasn't been implemented");
    } else { /* NOTE: I'll rewrite this block later. */
        // Exercise: 8-1: IPインタフェースの検索
        // ・送信元IPアドレス (src) に対応するIPインタフェースを検索
        //   ・インタフェースが見つからない場合はエラーを返す
        if (!(iface = ip_iface_select(src))) {
            errorf("IP interface which has selected source IP address is not found");
            return -1;
        }

        // Exercise: 8-2: 宛先へ到達可能か確認
        // ・宛先アドレス (dst) が以下の条件に合致しない場合はエラーを返す (到達不能)
        //   ・インタフェースのネットワークアドレスの範囲に含まれる
        //   ・ブロードキャストIPアドレス (255.255.255.255)
        if (dst == IP_ADDR_BROADCAST || (dst & iface->netmask) != (iface->unicast & iface->netmask)) {
            errorf("destination IP address (%s) is unreachable", ip_addr_ntop(dst, addr, sizeof(addr)));
            return -1;
        }
    }

    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too long, dev=%s, mtu=%u, < %zu", NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }

    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1) {
        errorf("ip_output_core() failure");
        return -1;
    }

    return len;
}

int ip_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    return 0;
}

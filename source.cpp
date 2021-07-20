#include <pthread.h>
#include <iostream>
#include <memory>
#include <functional>
#include <array>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>

extern "C" {
    #include <libnetfilter_queue/libnetfilter_queue.h>
    #include <libnetfilter_queue/pktbuff.h>
    #include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
    #include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
    #include <libnetfilter_queue/libnetfilter_queue_tcp.h>
}

#define THROW_IF_TRUE(x, m) do { if((x)) { throw std::runtime_error(m);}} while(false)

#define CONCAT_0(pre, post) pre ## post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)

using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {code}); (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)

struct tpool;
typedef struct tpool tpool_t;

typedef void (*thread_func_t)(void *arg);

tpool_t *tpool_create(size_t num);
void tpool_destroy(tpool_t *tm);

bool tpool_add_work(tpool_t *tm, thread_func_t func, void *arg);
void tpool_wait(tpool_t *tm);

struct tpool_work {
    thread_func_t      func;
    void              *arg;
    struct tpool_work *next;
};
typedef struct tpool_work tpool_work_t;

struct tpool {
    tpool_work_t    *work_first;
    tpool_work_t    *work_last;
    pthread_mutex_t  work_mutex;
    pthread_cond_t   work_cond;
    pthread_cond_t   working_cond;
    size_t           working_cnt;
    size_t           thread_cnt;
    bool             stop;
};

static tpool_work_t *tpool_work_create(thread_func_t func, void *arg)
{
    tpool_work_t *work;

    if (func == NULL)
        return NULL;

    work       = (tpool_work_t*)malloc(sizeof(*work));
    work->func = func;
    work->arg  = arg;
    work->next = NULL;
    return work;
}

static void tpool_work_destroy(tpool_work_t *work)
{
    if (work == NULL)
        return;
    free(work);
}

static tpool_work_t *tpool_work_get(tpool_t *tm)
{
    tpool_work_t *work;

    if (tm == NULL)
        return NULL;

    work = tm->work_first;
    if (work == NULL)
        return NULL;

    if (work->next == NULL) {
        tm->work_first = NULL;
        tm->work_last  = NULL;
    } else {
        tm->work_first = work->next;
    }

    return work;
}


static void *tpool_worker(void *arg)
{
    tpool_t      *tm =  (tpool_t*)arg;
    tpool_work_t *work;

    while (1) {
        pthread_mutex_lock(&(tm->work_mutex));

        while (tm->work_first == NULL && !tm->stop)
            pthread_cond_wait(&(tm->work_cond), &(tm->work_mutex));

        if (tm->stop)
            break;

        work = tpool_work_get(tm);
        tm->working_cnt++;
        pthread_mutex_unlock(&(tm->work_mutex));

        if (work != NULL) {
            work->func(work->arg);
            tpool_work_destroy(work);
        }

        pthread_mutex_lock(&(tm->work_mutex));
        tm->working_cnt--;
        if (!tm->stop && tm->working_cnt == 0 && tm->work_first == NULL)
            pthread_cond_signal(&(tm->working_cond));
        pthread_mutex_unlock(&(tm->work_mutex));
    }

    tm->thread_cnt--;
    pthread_cond_signal(&(tm->working_cond));
    pthread_mutex_unlock(&(tm->work_mutex));
    return NULL;
}

tpool_t *tpool_create(size_t num)
{
    tpool_t   *tm;
    pthread_t  thread;
    size_t     i;

    if (num == 0)
        num = 2;

    tm             =  (tpool_t*)calloc(1, sizeof(*tm));
    tm->thread_cnt = num;

    pthread_mutex_init(&(tm->work_mutex), NULL);
    pthread_cond_init(&(tm->work_cond), NULL);
    pthread_cond_init(&(tm->working_cond), NULL);

    tm->work_first = NULL;
    tm->work_last  = NULL;

    for (i=0; i<num; i++) {
        pthread_create(&thread, NULL, tpool_worker, tm);
        pthread_detach(thread);
    }

    return tm;
}

void tpool_destroy(tpool_t *tm)
{
    tpool_work_t *work;
    tpool_work_t *work2;

    if (tm == NULL)
        return;

    pthread_mutex_lock(&(tm->work_mutex));
    work = tm->work_first;
    while (work != NULL) {
        work2 = work->next;
        tpool_work_destroy(work);
        work = work2;
    }
    tm->stop = true;
    pthread_cond_broadcast(&(tm->work_cond));
    pthread_mutex_unlock(&(tm->work_mutex));

    tpool_wait(tm);

    pthread_mutex_destroy(&(tm->work_mutex));
    pthread_cond_destroy(&(tm->work_cond));
    pthread_cond_destroy(&(tm->working_cond));

    free(tm);
}

bool tpool_add_work(tpool_t *tm, thread_func_t func, void *arg)
{
    tpool_work_t *work;

    if (tm == NULL)
        return false;

    work = tpool_work_create(func, arg);
    if (work == NULL)
        return false;

    pthread_mutex_lock(&(tm->work_mutex));
    if (tm->work_first == NULL) {
        tm->work_first = work;
        tm->work_last  = tm->work_first;
    } else {
        tm->work_last->next = work;
        tm->work_last       = work;
    }

    pthread_cond_broadcast(&(tm->work_cond));
    pthread_mutex_unlock(&(tm->work_mutex));

    return true;
}

void tpool_wait(tpool_t *tm)
{
    if (tm == NULL)
        return;

    pthread_mutex_lock(&(tm->work_mutex));
    while (1) {
        if ((!tm->stop && tm->working_cnt != 0) || (tm->stop && tm->thread_cnt != 0)) {
            pthread_cond_wait(&(tm->working_cond), &(tm->work_mutex));
        } else {
            break;
        }
    }
    pthread_mutex_unlock(&(tm->work_mutex));
}

static const size_t num_threads = 128;

struct packetArgs {
    struct nfq_q_handle *queue;
    struct nfgenmsg *nfmsg;
    struct nfq_data *nfad;
    void *data;
    packetArgs(struct nfq_q_handle *m_queue, struct nfgenmsg *m_nfmsg, struct nfq_data *m_nfad, void *m_data) {
        queue = m_queue;
        nfmsg = m_nfmsg;
        nfad = m_nfad;
        data = m_data;
    }
};

#define PACKET_LEN (sizeof(struct iphdr) + sizeof(struct tcphdr))

void verdict_thread(void *args) {
    packetArgs *data = static_cast<packetArgs *>(args);
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(data->nfad);
    THROW_IF_TRUE(ph == nullptr, "Issue while packet header output.");

    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(data->nfad, &rawData);
    THROW_IF_TRUE(len < 0, "Can\'t get payload data output.");

    struct pkt_buff *pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate output.");
    SCOPED_GUARD(pktb_free(pkBuff););

    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    
    THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header output.");
    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header output.");

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
        THROW_IF_TRUE(tcp == nullptr, "Issue while tcp header.");
        //ip->version = 0x4;
        //ip->ihl = 0x5;
        //ip->tos = 0;
        ip->tot_len = htons(PACKET_LEN+len);
        //ip->id = 0;
        ip->frag_off = 0x0;//htons(IP_DF);
        //ip->ttl = 64;
        //ip->check = 0;
        
        tcp->doff = 0x6;
        tcp->window = htons(65535);
        //tcp->check = 0;
        //tcp->urg_ptr = 0;

        nfq_ip_set_checksum(ip);
        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        
        nfq_set_verdict(data->queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    } else nfq_set_verdict(data->queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
    delete args;
}

void input_verdict_thread(void *args) {
    packetArgs *data = static_cast<packetArgs *>(args);
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(data->nfad);
    THROW_IF_TRUE(ph == nullptr, "Issue while packet header.");

    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(data->nfad, &rawData);
    THROW_IF_TRUE(len < 0, "Can\'t get payload data.");

    struct pkt_buff *pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate.");
    SCOPED_GUARD(pktb_free(pkBuff););

    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);

    std::cout << sizeof(nfq_ip_get_hdr(pkBuff)) << std::endl;

    THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header.");
    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header.");
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
        THROW_IF_TRUE(tcp == nullptr, "Issue while tcp header.");
        nfq_ip_set_checksum(ip);
        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        nfq_set_verdict(data->queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    } else nfq_set_verdict(data->queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
    delete args;
}

tpool_t *tm;
tpool_t *input;

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
    return tpool_add_work(tm, verdict_thread, new packetArgs(queue, nfmsg, nfad, data));
}

static int input_netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
    return tpool_add_work(input, input_verdict_thread, new packetArgs(queue, nfmsg, nfad, data));
}

void* input_thread(void *arg) {
    std::cout << "Thread created" << std::endl;
    struct nfq_handle * handler_input = nfq_open();
    THROW_IF_TRUE(handler_input == nullptr, "Can\'t open nfqueue handler.");
    SCOPED_GUARD(nfq_close(handler_input););

    struct nfq_q_handle * queue_input = nfq_create_queue(handler_input, 1, input_netfilterCallback, nullptr);
    THROW_IF_TRUE(queue_input == nullptr, "Can\'t create queue handler.");
    SCOPED_GUARD(nfq_destroy_queue(queue_input););

    THROW_IF_TRUE(nfq_set_mode(queue_input, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");

    input = tpool_create(num_threads);

    int fd_input = nfq_fd(handler_input);
    std::array<char, 0x10000> buffer;
    for(;;) {
        int len = read(fd_input, buffer.data(), buffer.size());
        THROW_IF_TRUE(len < 0, "Issue while read");
        nfq_handle_packet(handler_input, buffer.data(), len);
    }
}

int main() {
    /*pthread_t id;
    pthread_create(&id, nullptr, input_thread, nullptr);*/

    struct nfq_handle * handler = nfq_open();
    THROW_IF_TRUE(handler == nullptr, "Can\'t open nfqueue handler.");
    SCOPED_GUARD(nfq_close(handler););

    struct nfq_q_handle * queue = nfq_create_queue(handler, 0, netfilterCallback, nullptr);
    THROW_IF_TRUE(queue == nullptr, "Can\'t create queue handler.");
    SCOPED_GUARD(nfq_destroy_queue(queue););

    THROW_IF_TRUE(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");

    tm   = tpool_create(num_threads);

    int fd = nfq_fd(handler);
    std::array<char, 0x10000> buffer;
    for(;;) {
        int len = read(fd, buffer.data(), buffer.size());
        THROW_IF_TRUE(len < 0, "Issue while read");
        nfq_handle_packet(handler, buffer.data(), len);
    }

    return 0;
}
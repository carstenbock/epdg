/*
 * epdg_tun_port.c — Erlang port program that owns a single Linux TUN
 * device (/dev/net/tun) and bridges it to the BEAM via stdio.
 *
 * Invocation:
 *     epdg_tun_port <ifname>
 *
 * The BEAM is expected to open the port with  {packet, 2} + binary, i.e.
 * every message on stdin/stdout is framed by a 2-byte big-endian length
 * prefix. The payload is a raw L3 IP packet (IFF_NO_PI).
 *
 *   stdin  (BEAM → port): L3 IP packet → write to TUN
 *   stdout (port → BEAM): L3 IP packet read from TUN
 *
 * The port exits on stdin EOF (BEAM closing the port) or any fatal
 * I/O error. Memory footprint is one 65 KiB read buffer.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -o epdg_tun_port epdg_tun_port.c
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>

#define MAX_FRAME 65535

static int tun_open(const char *ifname)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

/* Read exactly `n` bytes from fd or return -1 on EOF/error. */
static int read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char *)buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* Frame a packet for the BEAM's {packet,2} port and emit on stdout. */
static int emit_to_beam(const uint8_t *pkt, size_t len)
{
    if (len > 0xFFFF) return 0;
    uint8_t hdr[2];
    hdr[0] = (uint8_t)((len >> 8) & 0xFF);
    hdr[1] = (uint8_t)(len & 0xFF);
    if (write_full(STDOUT_FILENO, hdr, 2) < 0) return -1;
    if (len > 0 && write_full(STDOUT_FILENO, pkt, len) < 0) return -1;
    return 0;
}

/* Read one framed packet from the BEAM and return its length (0..65535)
 * or -1 on EOF / error. The caller must provide a buffer of MAX_FRAME.
 */
static int read_from_beam(uint8_t *buf)
{
    uint8_t hdr[2];
    if (read_full(STDIN_FILENO, hdr, 2) < 0) return -1;
    size_t len = ((size_t)hdr[0] << 8) | (size_t)hdr[1];
    if (len > MAX_FRAME) return -1;
    if (len == 0) return 0;
    if (read_full(STDIN_FILENO, buf, len) < 0) return -1;
    return (int)len;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <ifname>\n", argv[0]);
        return 2;
    }

    int tunfd = tun_open(argv[1]);
    if (tunfd < 0) {
        fprintf(stderr, "tun_open(%s): %s\n", argv[1], strerror(errno));
        return 1;
    }

    /* Non-blocking on the TUN side so a slow BEAM doesn't stall us. */
    int fl = fcntl(tunfd, F_GETFL, 0);
    if (fl >= 0) fcntl(tunfd, F_SETFL, fl | O_NONBLOCK);

    uint8_t buf[MAX_FRAME];
    struct pollfd pfds[2];
    pfds[0].fd = STDIN_FILENO;
    pfds[0].events = POLLIN;
    pfds[1].fd = tunfd;
    pfds[1].events = POLLIN;

    for (;;) {
        pfds[0].revents = 0;
        pfds[1].revents = 0;
        int pr = poll(pfds, 2, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* BEAM → TUN */
        if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (pfds[0].revents & POLLIN) {
            int n = read_from_beam(buf);
            if (n < 0) break;
            if (n > 0) {
                ssize_t w = write(tunfd, buf, (size_t)n);
                (void)w;  /* best-effort; drops are expected when the
                             kernel queue is full */
            }
        }

        /* TUN → BEAM (drain all available packets per wakeup). */
        if (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (pfds[1].revents & POLLIN) {
            for (;;) {
                ssize_t r = read(tunfd, buf, sizeof(buf));
                if (r < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    if (errno == EINTR) continue;
                    goto out;
                }
                if (r == 0) goto out;
                if (emit_to_beam(buf, (size_t)r) < 0) goto out;
            }
        }
    }

out:
    close(tunfd);
    return 0;
}

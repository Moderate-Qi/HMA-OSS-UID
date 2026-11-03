// Isolated host experiment: test whether returning an existing descriptor alone
// supplies seccomp listener semantics. Does not modify the Android implementation.
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void require(bool ok, const char* what) {
    if (!ok) { std::fprintf(stderr, "FAIL %s errno=%d\n", what, errno); _exit(1); }
}
static int install() {
    sock_filter code[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpriority, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{4, code};
    require(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
    int fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                     SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    require(fd >= 0, "create real listener");
    return fd;
}
static void send_fd(int socket, int fd) {
    char value = 'F'; iovec io{&value, 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(fd))]{};
    msghdr message{}; message.msg_iov = &io; message.msg_iovlen = 1;
    message.msg_control = control; message.msg_controllen = sizeof(control);
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    require(sendmsg(socket, &message, 0) == 1, "send real listener fd");
}
static int receive_fd(int socket) {
    char value; iovec io{&value, 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    msghdr message{}; message.msg_iov = &io; message.msg_iovlen = 1;
    message.msg_control = control; message.msg_controllen = sizeof(control);
    require(recvmsg(socket, &message, 0) == 1, "receive real listener fd");
    auto* header = CMSG_FIRSTHDR(&message);
    require(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS,
            "SCM_RIGHTS header");
    int fd; memcpy(&fd, CMSG_DATA(header), sizeof(fd)); return fd;
}
static pid_t query(int result_fd, int listener_fd) {
    pid_t child = fork(); require(child >= 0, "query fork");
    if (!child) {
        alarm(3); close(listener_fd);
        errno = 0; long answer[2]{syscall(__NR_getpriority, PRIO_USER, getuid()), errno};
        require(write(result_fd, answer, sizeof(answer)) == sizeof(answer), "query result");
        _exit(0);
    }
    return child;
}
static void run(int kind) {
    int pair[2]{-1,-1}; pid_t helper = -1;
    int listener;
    if (kind == 0) listener = install();
    else if (kind == 1) {
        listener = eventfd(0, EFD_CLOEXEC);
        require(listener >= 0, "create ordinary valid descriptor");
        seccomp_notif empty{}; errno = 0;
        int rc = ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &empty);
        require(rc == -1 && errno == ENOTTY, "ordinary fd lacks listener ioctl");
        std::printf("eventfd: descriptor valid, NOTIF_RECV=ENOTTY\n");
    } else {
        require(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == 0, "helper channel");
        helper = fork(); require(helper >= 0, "clean helper fork");
        if (!helper) {
            alarm(4); close(pair[0]); int fd = install(); send_fd(pair[1], fd);
            char done; require(read(pair[1], &done, 1) == 1, "helper lifetime");
            close(fd); _exit(0);
        }
        close(pair[1]); listener = receive_fd(pair[0]);
        uint64_t id = 0; errno = 0;
        int rc = ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id);
        require(rc == -1 && errno == ENOENT, "borrowed descriptor is real listener");
        std::printf("borrowed real listener: ID_VALID works, unknown id=ENOENT\n");
    }
    int result[2]; require(pipe(result) == 0, "query pipe");
    pid_t child = query(result[1], listener); close(result[1]);
    pollfd ready{listener, POLLIN, 0};
    int available = poll(&ready, 1, 120);
    bool notified = available > 0 && (ready.revents & POLLIN);
    if (notified) {
        seccomp_notif request{};
        require(ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) == 0, "receive query notification");
        seccomp_notif_resp response{}; response.id = request.id; response.val = 123;
        require(ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) == 0, "reply to query");
    }
    long answer[2]{};
    require(read(result[0], answer, sizeof(answer)) == sizeof(answer), "read query result");
    int status = 0; require(waitpid(child, &status, 0) == child && status == 0, "query exit");
    std::printf("%s: notification=%d query_result=%ld errno=%ld\n",
                kind == 0 ? "bound real listener" : kind == 1 ? "ordinary valid fd" : "borrowed real fd",
                int(notified), answer[0], answer[1]);
    require(kind == 0 ? notified && answer[0] == 123 : !notified && answer[0] >= 0,
            "descriptor ownership versus filter association");
    close(listener); close(result[0]);
    if (helper > 0) {
        require(write(pair[0], "X", 1) == 1, "release helper"); close(pair[0]);
        require(waitpid(helper, &status, 0) == helper && status == 0, "helper exit");
    }
}
int main() {
    alarm(8); setvbuf(stdout, nullptr, _IONBF, 0);
    for (int kind = 0; kind < 3; ++kind) {
        pid_t child = fork(); require(child >= 0, "isolated case fork");
        if (!child) { alarm(5); run(kind); _exit(0); }
        int status = 0; require(waitpid(child, &status, 0) == child && status == 0, "isolated case exit");
    }
    std::puts("PASS: allocating or transferring an fd alone does not associate it with the target filter.");
}

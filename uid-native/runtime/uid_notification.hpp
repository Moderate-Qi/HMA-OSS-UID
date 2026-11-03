#pragma once
#include "uid_rule.hpp"
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <cstring>

// Protocol/notification strategy adapted from longze777/UID- 32b9924,
// Apache-2.0. Target membership remains the caller's own HMA snapshot.
namespace hma_uid::notification {
struct Hello { uint32_t version=3, pid=0, tid=0, uid=0, hiddenCount=0; };
inline bool transfer(int socket, void* data, size_t size, bool sending) {
    auto* bytes=static_cast<char*>(data);
    while(size) {
        pollfd descriptor{socket,static_cast<short>(sending?POLLOUT:POLLIN),0};
        int ready;do{ready=poll(&descriptor,1,3000);}while(ready<0&&errno==EINTR);
        if(ready<=0)return false;
        const ssize_t n=sending?send(socket,bytes,size,MSG_NOSIGNAL):recv(socket,bytes,size,0);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return false;
        bytes+=n;size-=size_t(n);
    }
    return true;
}
inline bool prepare(int socket,uint32_t uid,const std::vector<uint32_t>& hidden={}) {
    Hello hello{3,uint32_t(getpid()),uint32_t(gettid()),uid,uint32_t(hidden.size())};char ready=0;
    return hidden.size()<=128&&transfer(socket,&hello,sizeof(hello),true)&&
        (hidden.empty()||transfer(socket,const_cast<uint32_t*>(hidden.data()),hidden.size()*sizeof(uint32_t),true))&&
        transfer(socket,&ready,1,false)&&ready=='R';
}
enum class Delivery { failed, sent, acknowledged };
inline Delivery send_listener(int socket,int fd) {
    char byte='F';alignas(cmsghdr) char control[CMSG_SPACE(sizeof(fd))]{};
    iovec payload{&byte,1};msghdr message{};
    message.msg_iov=&payload;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);
    auto* header=CMSG_FIRSTHDR(&message);header->cmsg_level=SOL_SOCKET;header->cmsg_type=SCM_RIGHTS;
    header->cmsg_len=CMSG_LEN(sizeof(fd));memcpy(CMSG_DATA(header),&fd,sizeof(fd));
    ssize_t result;do{result=sendmsg(socket,&message,MSG_NOSIGNAL);}while(result<0&&errno==EINTR);
    if(result!=1)return Delivery::failed;
    char attached=0;
    return transfer(socket,&attached,1,false)&&attached=='A' ? Delivery::acknowledged : Delivery::sent;
}
inline std::vector<sock_filter> rule(const std::vector<uint32_t>& hidden) {
#if defined(__aarch64__)
    constexpr uint32_t arch=AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
    constexpr uint32_t arch=AUDIT_ARCH_X86_64; // host behavioural tests only
#else
#error Unsupported notification ABI
#endif
    (void)hidden; // Membership is checked in the root companion, not globally denied.
    std::vector<sock_filter> code={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,arch,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_clone,6,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_clone3,5,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_seccomp,4,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_prctl,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_SET_SECCOMP,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),
    };
    // Existing ALLOW paths fall through to these tests. Only the four seccomp
    // notification ioctl requests are delegated; all other ioctl traffic stays
    // in the kernel. This is needed to service app-owned listener descriptors.
    code.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr)));
    code.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_ioctl,0,7));
    code.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,args[1])));
    code.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SECCOMP_IOCTL_NOTIF_RECV,4,0));
    code.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SECCOMP_IOCTL_NOTIF_SEND,3,0));
    code.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SECCOMP_IOCTL_NOTIF_ID_VALID,2,0));
    code.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SECCOMP_IOCTL_NOTIF_ADDFD,1,0));
    code.push_back(BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW));
    code.push_back(BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF));
    code.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr)));
    code.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_getpriority,0,3));
    code.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,args[0])));
    code.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PRIO_USER,0,1));
    code.push_back(BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF));
    code.push_back(BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW));
    return code;
}
inline int install(const std::vector<sock_filter>& code) {
    sock_fprog program{static_cast<unsigned short>(code.size()),const_cast<sock_filter*>(code.data())};
    return syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&program);
}
void companion(int client);
}

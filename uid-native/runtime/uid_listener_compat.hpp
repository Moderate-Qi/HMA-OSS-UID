#pragma once
// Optional nested getpriority notification compatibility. The descriptor is a
// real kernel seccomp notification descriptor; no application library hooks.
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <vector>
#include <array>
#include <set>
#include <deque>
#include <utility>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <climits>
#include <tuple>
#include <algorithm>

namespace hma_uid::notification {
// Conservative control-flow proof. Any notification return must be guarded by
// the compiled ABI, getpriority and PRIO_USER. This accepts policy shapes rather
// than package names or a particular detector's instruction sequence.
inline bool compatible_listener_program(const std::vector<sock_filter>& p) {
    if(p.empty()||p.size()>512)return false;
#if defined(__aarch64__)
    constexpr uint32_t arch=AUDIT_ARCH_AARCH64;
#else
    constexpr uint32_t arch=AUDIT_ARCH_X86_64;
#endif
    struct Point {size_t pc;int origin;unsigned guards;};
    std::vector<Point> todo{{0,-1,0}};
    std::set<std::tuple<size_t,int,unsigned>> seen;
    bool notified=false;
    while(!todo.empty()) {
        auto n=todo.back();todo.pop_back();
        if(n.pc>=p.size()||seen.size()>32768)return false;
        if(!seen.emplace(n.pc,n.origin,n.guards).second)continue;
        auto op=p[n.pc];
        if(op.code==(BPF_RET|BPF_K)) {
            if(op.k==SECCOMP_RET_ALLOW)continue;
            if(op.k!=SECCOMP_RET_USER_NOTIF||n.guards!=7)return false;
            notified=true;continue;
        }
        if(op.code==(BPF_LD|BPF_W|BPF_ABS)) {
            if(op.k%4||op.k>sizeof(seccomp_data)-4)return false;
            n.origin=int(op.k);++n.pc;todo.push_back(n);continue;
        }
        if(op.code==(BPF_LD|BPF_W|BPF_IMM)) {n.origin=-1;++n.pc;todo.push_back(n);continue;}
        if(op.code==(BPF_JMP|BPF_JA)) {
            if(op.k>=p.size()-n.pc-1)return false;
            n.pc+=op.k+1;todo.push_back(n);continue;
        }
        if(op.code==(BPF_JMP|BPF_JEQ|BPF_K)) {
            if(size_t(op.jt)>=p.size()-n.pc-1||size_t(op.jf)>=p.size()-n.pc-1)return false;
            unsigned guard=0;uint32_t target=0;
            if(n.origin==int(offsetof(seccomp_data,arch))){guard=1;target=arch;}
            else if(n.origin==int(offsetof(seccomp_data,nr))){guard=2;target=__NR_getpriority;}
            else if(n.origin==int(offsetof(seccomp_data,args[0]))){guard=4;target=PRIO_USER;}
            auto yes=n,no=n;yes.pc+=op.jt+1;no.pc+=op.jf+1;
            if(guard&&(n.guards&guard)) {todo.push_back(op.k==target?yes:no);continue;}
            if(guard&&op.k==target)yes.guards|=guard;
            todo.push_back(yes);todo.push_back(no);continue;
        }
        // Unsupported instructions retain the real kernel install result.
        return false;
    }
    return notified;
}

class ListenerCarrier {
    int fd_=-1,control_=-1,pidfd_=-1;
    pid_t child_=-1;
    bool wake_=false,closed_=false;
    std::vector<std::pair<int,int>> owners_;
    static bool send_fd(int channel,int fd) {
        char byte='L';iovec data{&byte,1};alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))]{};
        msghdr msg{};msg.msg_iov=&data;msg.msg_iovlen=1;msg.msg_control=ancillary;msg.msg_controllen=sizeof(ancillary);
        auto* header=CMSG_FIRSTHDR(&msg);header->cmsg_level=SOL_SOCKET;header->cmsg_type=SCM_RIGHTS;
        header->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(header),&fd,sizeof(fd));
        return sendmsg(channel,&msg,MSG_NOSIGNAL)==1;
    }
    [[noreturn]] static void donor(int channel,pid_t parent,const std::vector<sock_filter>& program) {
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(1);
        if(channel!=3&&dup2(channel,3)!=3)_exit(1);
        if(syscall(__NR_close_range,4u,~0u,0u))_exit(1);
        if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))_exit(1);
        sock_fprog app{static_cast<unsigned short>(program.size()),const_cast<sock_filter*>(program.data())};
        if(syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,0,&app))_exit(1);
        sock_filter code[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_getpriority,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
        sock_fprog policy{4,code};
        int listener=syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&policy);
        if(listener<0||!send_fd(3,listener))_exit(1);
        close(listener);
        char command;
        while(read(3,&command,1)==1&&command=='W')syscall(__NR_getpriority,PRIO_USER,getuid());
        _exit(0);
    }
public:
    std::deque<uint64_t> queued,receivers;
    ListenerCarrier(){owners_.reserve(8);}
    ListenerCarrier(const ListenerCarrier&)=delete;
    ~ListenerCarrier(){stop();}
    void stop() noexcept {
        closed_=true;
        if(pidfd_>=0){syscall(__NR_pidfd_send_signal,pidfd_,SIGKILL,nullptr,0);close(pidfd_);pidfd_=-1;}
        if(control_>=0){close(control_);control_=-1;}
        if(fd_>=0){close(fd_);fd_=-1;}
        if(child_>0){int status;while(waitpid(child_,&status,0)<0&&errno==EINTR){}child_=-1;}
    }
    bool create(const std::vector<sock_filter>& program,int tid) {
        // Permission/support preflight before exporting a descriptor.
        errno=0;long compared=syscall(__NR_kcmp,getpid(),tid,0,0,~0ul);
        if(compared>=0||errno!=EBADF)return false;
        int pair[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair))return false;
        pid_t parent=getpid();child_=fork();
        if(child_==0)donor(pair[1],parent,program);
        close(pair[1]);control_=pair[0];if(child_<0)return false;
        pidfd_=syscall(__NR_pidfd_open,child_,0);if(pidfd_<0)return false;
        pollfd wait{control_,POLLIN,0};if(poll(&wait,1,500)<=0)return false;
        char byte=0;iovec payload{&byte,1};alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))]{};
        msghdr msg{};msg.msg_iov=&payload;msg.msg_iovlen=1;msg.msg_control=ancillary;msg.msg_controllen=sizeof(ancillary);
        ssize_t n=recvmsg(control_,&msg,MSG_CMSG_CLOEXEC);auto* header=CMSG_FIRSTHDR(&msg);
        if(n!=1||byte!='L'||!header||header->cmsg_level!=SOL_SOCKET||header->cmsg_type!=SCM_RIGHTS||header->cmsg_len!=CMSG_LEN(sizeof(int)))return false;
        memcpy(&fd_,CMSG_DATA(header),sizeof(fd_));return !(msg.msg_flags&MSG_CTRUNC)&&fd_>=0;
    }
    int fd()const{return fd_;}
    bool closed()const{return closed_;}
    bool same(int tid,int fd)const {
        return !closed_&&syscall(__NR_kcmp,getpid(),tid,0,fd_,fd)==0;
    }
    void owner(int tid,int fd) {
        std::pair<int,int> item{tid,fd};
        if(std::find(owners_.begin(),owners_.end(),item)==owners_.end())owners_.push_back(item);
    }
    void exported(int tid,int fd) {owners_.front()={tid,fd};}
    bool alive(const std::vector<int>& tasks) {
        if(closed_)return false;
        for(auto& owner:owners_)if(same(owner.first,owner.second))return true;
        // Duplication and inherited descriptors are located only after known
        // owners close; normal notification traffic needs one kcmp operation.
        for(int tid:tasks) {
            char path[64];snprintf(path,sizeof(path),"/proc/%d/fd",tid);
            DIR* dir=opendir(path);if(!dir)continue;
            while(auto* e=readdir(dir)) {
                char* end;long fd=strtol(e->d_name,&end,10);
                if(*end||fd<0||fd>INT_MAX)continue;
                if(same(tid,int(fd))){closedir(dir);owner(tid,int(fd));return true;}
            }
            closedir(dir);
        }
        stop();return false;
    }
    bool signal() {
        if(closed_||wake_||queued.empty())return true;
        char command='W';if(send(control_,&command,1,MSG_NOSIGNAL)!=1)return false;
        wake_=true;return true;
    }
    bool needs_drain()const{return !closed_&&wake_&&queued.empty();}
    bool drain() {
        if(!needs_drain())return true;
        pollfd ready{fd_,POLLIN,0};if(poll(&ready,1,0)<=0)return true;
        seccomp_notif event{};if(ioctl(fd_,SECCOMP_IOCTL_NOTIF_RECV,&event))return false;
        seccomp_notif_resp response{};response.id=event.id;
        if(ioctl(fd_,SECCOMP_IOCTL_NOTIF_SEND,&response)&&errno!=ENOENT)return false;
        wake_=false;return true;
    }
};
}

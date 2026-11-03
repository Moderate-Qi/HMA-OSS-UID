// Adapted from longze777/UID- 32b9924 (Apache-2.0). See UID-LICENSE.
#include "uid_notification.hpp"
#include "fork_events.hpp"
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <map>
#include <memory>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <array>
#include "uid_listener_compat.hpp"
#ifdef __ANDROID__
#include <android/log.h>
#endif

namespace hma_uid::notification {
namespace {
void paused(int tid,const char* reason) {
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_WARN,"HMA-UID","tid=%d filtering paused: %s",tid,reason);
#else
    fprintf(stderr,"HMA-UID tid=%d filtering paused: %s\n",tid,reason);
#endif
}
using Program=std::vector<sock_filter>;
struct Policy { std::shared_ptr<const Program> program;std::shared_ptr<ListenerCarrier> listener; };
using Policies=std::vector<Policy>;
struct State {
    int count=-1,tracer=-1;
    std::shared_ptr<const Program> pending;
    Policies installed;
};
struct Identity {int tgid=-1,uid=-1,count=-1,tracer=-1;};
bool status(int tid,Identity& result) {
    char path[64];snprintf(path,sizeof(path),"/proc/%d/status",tid);
    FILE* file=fopen(path,"re");if(!file)return false;
    char line[256];
    while(fgets(line,sizeof(line),file)) {
        if(sscanf(line,"Tgid: %d",&result.tgid)==1)continue;
        if(sscanf(line,"Uid: %d",&result.uid)==1)continue;
        if(sscanf(line,"Seccomp_filters: %d",&result.count)==1)continue;
        sscanf(line,"TracerPid: %d",&result.tracer);
    }
    fclose(file);return result.tgid>0&&result.count>=0&&result.tracer>=0;
}
bool read_memory(int tid,uint64_t address,void* output,size_t size) {
    iovec local{output,size},remote{reinterpret_cast<void*>(address),size};
    return process_vm_readv(tid,&local,1,&remote,1,0)==ssize_t(size);
}
bool write_memory(int tid,uint64_t address,const void* input,size_t size) {
    iovec local{const_cast<void*>(input),size},remote{reinterpret_cast<void*>(address),size};
    return process_vm_writev(tid,&local,1,&remote,1,0)==ssize_t(size);
}
bool evaluate(const Program& program,const seccomp_data& data,uint32_t& result) {
    uint32_t a=0,x=0,memory[BPF_MEMWORDS]{};
    for(size_t pc=0;pc<program.size();++pc) {
        const auto& op=program[pc];const uint32_t v=BPF_SRC(op.code)==BPF_X?x:op.k;
        switch(BPF_CLASS(op.code)) {
        case BPF_LD:case BPF_LDX: {
            uint32_t value;
            if(BPF_MODE(op.code)==BPF_IMM)value=op.k;
            else if(BPF_MODE(op.code)==BPF_LEN)value=sizeof(data);
            else if(BPF_MODE(op.code)==BPF_MEM&&op.k<BPF_MEMWORDS)value=memory[op.k];
            else if(BPF_CLASS(op.code)==BPF_LD&&BPF_MODE(op.code)==BPF_ABS&&BPF_SIZE(op.code)==BPF_W&&op.k<=sizeof(data)-4)
                memcpy(&value,reinterpret_cast<const char*>(&data)+op.k,4);
            else return false;
            if(BPF_CLASS(op.code)==BPF_LD)a=value;else x=value;break;
        }
        case BPF_ST:if(op.k>=BPF_MEMWORDS)return false;memory[op.k]=a;break;
        case BPF_STX:if(op.k>=BPF_MEMWORDS)return false;memory[op.k]=x;break;
        case BPF_ALU:
            switch(BPF_OP(op.code)) {
            case BPF_ADD:a+=v;break;case BPF_SUB:a-=v;break;case BPF_MUL:a*=v;break;
            case BPF_DIV:if(!v){result=0;return true;}a/=v;break;
            case BPF_MOD:if(!v){result=0;return true;}a%=v;break;
            case BPF_OR:a|=v;break;case BPF_AND:a&=v;break;case BPF_XOR:a^=v;break;
            case BPF_LSH:a=v<32?a<<v:0;break;case BPF_RSH:a=v<32?a>>v:0;break;
            case BPF_NEG:a=0-a;break;default:return false;
            }break;
        case BPF_JMP: {
            size_t skip;
            switch(BPF_OP(op.code)) {
            case BPF_JA:skip=op.k;break;case BPF_JEQ:skip=a==v?op.jt:op.jf;break;
            case BPF_JGT:skip=a>v?op.jt:op.jf;break;case BPF_JGE:skip=a>=v?op.jt:op.jf;break;
            case BPF_JSET:skip=(a&v)?op.jt:op.jf;break;default:return false;
            }
            if(skip>=program.size()-pc)return false;pc+=skip;break;
        }
        case BPF_RET:result=BPF_RVAL(op.code)==BPF_A?a:op.k;return true;
        case BPF_MISC:
            if(BPF_MISCOP(op.code)==BPF_TAX)x=a;else if(BPF_MISCOP(op.code)==BPF_TXA)a=x;else return false;
            break;
        default:return false;
        }
    }
    return false;
}
class Session {
    struct Event {bool fork;uint32_t tid,parent;uint64_t time;};
    std::map<int,State> states_;
    std::map<int,std::unique_ptr<ForkEvents>> watches_;
    bool healthy_=true;
    bool compatHealthy_=true;
    bool deferred_=false;
    int listener_=-1;
    std::vector<uint32_t> hidden_;
    std::vector<std::shared_ptr<ListenerCarrier>> carriers_;
    struct Pending {seccomp_notif request;std::shared_ptr<ListenerCarrier> listener;bool received=false;};
    std::map<uint64_t,Pending> pending_;
    std::map<uint64_t,seccomp_notif> receives_;
    bool valid(uint64_t id) {return ioctl(listener_,SECCOMP_IOCTL_NOTIF_ID_VALID,&id)==0;}
    bool hidden(const seccomp_data& call)const {
        return std::find(hidden_.begin(),hidden_.end(),uint32_t(call.args[1]))!=hidden_.end();
    }
    void reply(uint64_t id,int error=0,int64_t value=0,uint32_t flags=0) {
        seccomp_notif_resp r{};r.id=id;r.error=error;r.val=value;r.flags=flags;
        int sent;do{sent=ioctl(listener_,SECCOMP_IOCTL_NOTIF_SEND,&r);}while(sent<0&&errno==EINTR);
    }
    static void result(seccomp_notif_resp& r,int error=0,int64_t value=0) {r.flags=0;r.error=error;r.val=value;}
    bool carrier_alive(const std::shared_ptr<ListenerCarrier>& c) {
        // An in-flight RECV holds a logical listener reference, just like the
        // kernel ioctl holds its struct file even after another thread closes.
        for(auto id:c->receivers)if(valid(id))return true;
        std::vector<int> tasks;for(const auto& p:states_)tasks.push_back(p.first);
        return c->alive(tasks);
    }
    void collect_closed() {
        // A creator's perf context reports child births, but a leaf child can
        // exit without ever getting its own context. Reaped leaves must not
        // retain policy/listener references across repeated disposable probes.
        for(auto p=states_.begin();p!=states_.end();) {
            char path[64];snprintf(path,sizeof(path),"/proc/%d",p->first);
            if(access(path,F_OK)&&errno==ENOENT){watches_.erase(p->first);p=states_.erase(p);}else ++p;
        }
        for(auto p=pending_.begin();p!=pending_.end();) {
            if(!valid(p->first))p=pending_.erase(p);
            else if(!carrier_alive(p->second.listener)){reply(p->first,-ENOSYS);p=pending_.erase(p);}
            else ++p;
        }
        for(auto p=receives_.begin();p!=receives_.end();) {
            if(!valid(p->first))p=receives_.erase(p);else ++p;
        }
        for(auto& c:carriers_) {
            auto& q=c->queued;q.erase(std::remove_if(q.begin(),q.end(),[&](auto id){return !pending_.count(id);}),q.end());
            auto& r=c->receivers;r.erase(std::remove_if(r.begin(),r.end(),[&](auto id){return !receives_.count(id);}),r.end());
        }
        carriers_.erase(std::remove_if(carriers_.begin(),carriers_.end(),[](const auto& c){return c.use_count()==1||c->closed();}),carriers_.end());
    }
    void complete_receives(const std::shared_ptr<ListenerCarrier>& carrier) {
        while(!carrier->queued.empty()&&!carrier->receivers.empty()) {
            auto q=carrier->queued.front(),receive=carrier->receivers.front();
            auto p=pending_.find(q);auto receiver=receives_.find(receive);
            if(p==pending_.end()||!valid(q)){carrier->queued.pop_front();pending_.erase(q);continue;}
            if(receiver==receives_.end()||!valid(receive)){carrier->receivers.pop_front();receives_.erase(receive);continue;}
            if(!write_memory(receiver->second.pid,receiver->second.data.args[2],&p->second.request,sizeof(seccomp_notif))) {
                reply(receive,-EFAULT);carrier->receivers.pop_front();receives_.erase(receive);continue;
            }
            p->second.received=true;reply(receive);carrier->queued.pop_front();carrier->receivers.pop_front();receives_.erase(receive);
        }
        if(!carrier->signal()||!carrier->drain())compatHealthy_=false;
    }
    bool app_ioctl(const seccomp_notif& request,seccomp_notif_resp& response) {
        if(request.data.nr!=__NR_ioctl)return false;
        auto carrier=std::find_if(carriers_.begin(),carriers_.end(),[&](const auto& p){return p->same(request.pid,int(request.data.args[0]));});
        if(carrier==carriers_.end())return false;
        const auto& c=*carrier;c->owner(request.pid,int(request.data.args[0]));
        uint32_t command=uint32_t(request.data.args[1]);uint64_t address=request.data.args[2];
        if(command==SECCOMP_IOCTL_NOTIF_RECV) {
            seccomp_notif zero{},input{};
            if(!read_memory(request.pid,address,&input,sizeof(input))){result(response,-EFAULT);return true;}
            if(memcmp(&input,&zero,sizeof(input))){result(response,-EINVAL);return true;}
            if(receives_.size()>=32){result(response,-EAGAIN);return true;}
            receives_[request.id]=request;c->receivers.push_back(request.id);deferred_=true;
            complete_receives(c);return true;
        }
        if(command==SECCOMP_IOCTL_NOTIF_ID_VALID) {
            uint64_t id;if(!read_memory(request.pid,address,&id,sizeof(id))){result(response,-EFAULT);return true;}
            auto p=pending_.find(id);
            result(response,p!=pending_.end()&&p->second.listener==c&&p->second.received&&valid(id)?0:-ENOENT);return true;
        }
        if(command==SECCOMP_IOCTL_NOTIF_SEND) {
            seccomp_notif_resp r{};
            if(!read_memory(request.pid,address,&r,sizeof(r))){result(response,-EFAULT);return true;}
            if((r.flags&~SECCOMP_USER_NOTIF_FLAG_CONTINUE)||
               ((r.flags&SECCOMP_USER_NOTIF_FLAG_CONTINUE)&&(r.error||r.val))){result(response,-EINVAL);return true;}
            auto p=pending_.find(r.id);
            if(p==pending_.end()||p->second.listener!=c||!p->second.received||!valid(r.id)){result(response,-ENOENT);return true;}
            if((r.flags&SECCOMP_USER_NOTIF_FLAG_CONTINUE)&&hidden(p->second.request.data)){r.flags=0;r.error=-ESRCH;}
            int sent;do{sent=ioctl(listener_,SECCOMP_IOCTL_NOTIF_SEND,&r);}while(sent<0&&errno==EINTR);
            result(response,sent?-errno:0);pending_.erase(p);return true;
        }
        if(command==SECCOMP_IOCTL_NOTIF_ADDFD) {
            seccomp_notif_addfd add{};
            if(!read_memory(request.pid,address,&add,sizeof(add))){result(response,-EFAULT);return true;}
            auto p=pending_.find(add.id);
            if(p==pending_.end()||p->second.listener!=c||!p->second.received){result(response,-ENOENT);return true;}
            int pidfd=syscall(__NR_pidfd_open,request.pid,0);
            if(pidfd<0){result(response,-errno);return true;}
            int source=syscall(__NR_pidfd_getfd,pidfd,add.srcfd,0);int saved=errno;close(pidfd);
            if(source<0){result(response,-saved);return true;}
            add.srcfd=uint32_t(source);int added=ioctl(listener_,SECCOMP_IOCTL_NOTIF_ADDFD,&add);saved=errno;close(source);
            result(response,added<0?-saved:0,added<0?0:added);
            if(added>=0&&(add.flags&SECCOMP_ADDFD_FLAG_SEND))pending_.erase(p);
            return true;
        }
        return false;
    }
    bool new_listener(const seccomp_notif& request,seccomp_notif_resp& response,State& state,const std::shared_ptr<Program>& program) {
        if(!compatible_listener_program(*program))return false;
        collect_closed();
        for(const auto& installed:state.installed)if(installed.listener&&carrier_alive(installed.listener)) {
            result(response,-EBUSY);return true;
        }
        collect_closed();if(carriers_.size()>=8)return false;
        auto carrier=std::make_shared<ListenerCarrier>();
        if(!carrier->create(*program,request.pid))return false;
        state.installed.reserve(state.installed.size()+1);
        carrier->owner(request.pid,-1);
        seccomp_notif_addfd add{};add.id=request.id;add.srcfd=carrier->fd();add.newfd_flags=O_CLOEXEC;
        int fd=ioctl(listener_,SECCOMP_IOCTL_NOTIF_ADDFD,&add);
        if(fd<0)return false;
        carrier->exported(request.pid,fd);carriers_.push_back(carrier);
        state.installed.push_back({program,carrier});result(response,0,fd);return true;
    }
    bool watch(int tid) {
        if(watches_.count(tid))return true;
        if(watches_.size()>=128)return false;
        auto events=std::make_unique<ForkEvents>();if(!events->open(tid))return false;
        watches_[tid]=std::move(events);return true;
    }
    bool births() {
        std::vector<Event> events;
        for(auto& watch:watches_) {
            if(!watch.second->drain([&](bool fork,uint32_t tid,uint32_t parent,uint32_t,uint64_t time){events.push_back({fork,tid,parent,time});}))return false;
        }
        std::stable_sort(events.begin(),events.end(),[](const auto& a,const auto& b){return a.time<b.time;});
        for(const auto& event:events) {
            if(event.fork) {
                const auto parent=states_.find(event.parent);
                if(parent==states_.end())return false;
                // Snapshot the actual creating thread, not the process leader.
                // Immutable programs are shared; each child gets its own list.
                State child=parent->second;states_[event.tid]=std::move(child);
                watches_.erase(event.tid);
            } else {states_.erase(event.tid);watches_.erase(event.tid);}
        }
        if(!events.empty())collect_closed();
        if(states_.size()>4096)return false;
        return true;
    }
    bool settle(int tid,State& state) {
        if(!state.pending)return true;
        Identity now;if(!status(tid,now))return false;
        if(now.count==state.count+1)state.installed.push_back({state.pending,{}});
        else if(now.count!=state.count)return false;
        state.pending.reset();state.count=now.count;state.tracer=now.tracer;return true;
    }
    bool respond(const seccomp_notif& request,seccomp_notif_resp& response) {
        if(!births())return false;
        if(app_ioctl(request,response))return true;
        auto position=states_.find(request.pid);if(position==states_.end())return false;
        auto& state=position->second;if(!settle(request.pid,state))return false;
        const auto& call=request.data;
        const bool prctl_install=call.nr==__NR_prctl&&uint32_t(call.args[0])==PR_SET_SECCOMP&&uint32_t(call.args[1])==SECCOMP_MODE_FILTER;
        const bool seccomp_install=call.nr==__NR_seccomp&&uint32_t(call.args[0])==SECCOMP_SET_MODE_FILTER;
        if(prctl_install||seccomp_install) {
            // Do not invent a per-thread interpretation of a synchronized policy.
            if(seccomp_install&&(call.args[1]&SECCOMP_FILTER_FLAG_TSYNC)) {
                paused(request.pid,"synchronized app policy; preserving kernel semantics");
                return false;
            }
            Identity now;if(!status(request.pid,now))return false;
            state.count=now.count;state.tracer=now.tracer;
            sock_fprog program{};
            // Invalid pointers/lengths retain the kernel's own rejection.
            if(!read_memory(request.pid,call.args[2],&program,sizeof(program))) {
                if(errno==EPERM||errno==EACCES||errno==ENOSYS)return false;
                return true;
            }
            if(!program.len||program.len>BPF_MAXINSNS)return true;
            auto copy=std::make_shared<Program>(program.len);
            if(!read_memory(request.pid,reinterpret_cast<uint64_t>(program.filter),copy->data(),copy->size()*sizeof(sock_filter))) {
                if(errno==EPERM||errno==EACCES||errno==ENOSYS)return false;
                return true;
            }
            if(seccomp_install&&call.args[1]==SECCOMP_FILTER_FLAG_NEW_LISTENER&&new_listener(request,response,state,copy))return true;
            state.pending=std::move(copy);return true;
        }
        if(call.nr==__NR_clone||call.nr==__NR_clone3) {
            // Arm this creator before CONTINUE. Its FORK record is published
            // before the new task can send its first notification.
            return watch(request.pid);
        }
        if(call.nr!=__NR_getpriority)return true;
        uint32_t action=SECCOMP_RET_ALLOW;std::shared_ptr<ListenerCarrier> carrier;
        for(auto program=state.installed.rbegin();program!=state.installed.rend();++program) {
            uint32_t result;if(!evaluate(*program->program,call,result))return false;
            if(int32_t(result&SECCOMP_RET_ACTION_FULL)<int32_t(action&SECCOMP_RET_ACTION_FULL)){action=result;carrier=program->listener;}
        }
        action&=SECCOMP_RET_ACTION_FULL;
        if(action==SECCOMP_RET_USER_NOTIF&&carrier) {
            if(!carrier_alive(carrier)){result(response,-ENOSYS);return true;}
            if(pending_.size()>=512){result(response,-EAGAIN);return true;}
            pending_[request.id]={request,carrier,false};carrier->queued.push_back(request.id);deferred_=true;
            complete_receives(carrier);return true;
        }
        if(action==SECCOMP_RET_TRACE) {
            if(state.tracer!=0)return false;
            response.flags=0;response.error=-ENOSYS;return true;
        }
        if(action!=SECCOMP_RET_ALLOW&&action!=SECCOMP_RET_LOG)return false;
        if(hidden(call)){response.flags=0;response.error=-ESRCH;}
        return true;
    }
public:
    bool prepare(int tid,std::vector<uint32_t> hidden) {carriers_.reserve(8);hidden_=std::move(hidden);states_[tid]=State{};return watch(tid);}
    void serve(int listener) noexcept {
        listener_=listener;
        for(;;) {
            // Task observers can retain task references. Drain EXIT records
            // even when no further syscall notification arrives, otherwise an
            // ended app can leave a companion session alive indefinitely.
            std::array<pollfd,145> descriptors{};size_t count=1;
            descriptors[0]={listener,POLLIN,0};
            for(const auto& watch:watches_)descriptors[count++]={watch.second->fd(),POLLIN,0};
            const size_t task_end=count;
            for(const auto& c:carriers_)if(c->needs_drain())descriptors[count++]={c->fd(),POLLIN,0};
            int ready;do{ready=poll(descriptors.data(),count,pending_.empty()&&receives_.empty()?-1:50);}while(ready<0&&errno==EINTR);
            if(ready<0||(descriptors[0].revents&(POLLHUP|POLLERR|POLLNVAL)))break;
            if(ready==0){try{collect_closed();}catch(...){healthy_=false;}continue;}
            if(healthy_) {
                bool task_event=false;
                for(size_t n=1;n<task_end;++n)if(descriptors[n].revents)task_event=true;
                if(task_event) {
                    try{healthy_=births();}catch(...){healthy_=false;}
                    if(!healthy_){paused(0,"task observation unavailable");states_.clear();watches_.clear();}
                    else if(states_.empty())break;
                }
                for(const auto& c:carriers_)if(!c->drain())healthy_=false;
            }
            if(!(descriptors[0].revents&POLLIN))continue;
            seccomp_notif request{};
            if(ioctl(listener,SECCOMP_IOCTL_NOTIF_RECV,&request)) {if(errno==EINTR||errno==ENOENT)continue;break;}
            int valid;
            do{valid=ioctl(listener,SECCOMP_IOCTL_NOTIF_ID_VALID,&request.id);}while(valid<0&&errno==EINTR);
            if(valid)continue;
            seccomp_notif_resp response{};response.id=request.id;response.flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            deferred_=false;
            if(healthy_) {
                try{healthy_=respond(request,response)&&compatHealthy_;}catch(...){healthy_=false;}
                if(!healthy_) {
                    paused(request.pid,"unsupported or lost policy state");
                    // Unknown/lost state must not fabricate ESRCH or prevent
                    // ordinary process creation. Keep draining until task exit.
                    response={};response.id=request.id;response.flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                    states_.clear();watches_.clear();
                    for(const auto& p:pending_)reply(p.first,-ENOSYS);
                    for(const auto& p:receives_)reply(p.first,-ENOSYS);
                    pending_.clear();receives_.clear();deferred_=false;
                }
            }
            // A paused engine must not expose a carrier's housekeeping
            // notification as if it were an application's own notification.
            if(!healthy_&&request.data.nr==__NR_ioctl)result(response,-ENOSYS);
            if(deferred_)continue;
            int sent;
            do{sent=ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&response);}while(sent<0&&errno==EINTR);
            if(sent&&errno!=ENOENT)break;
        }
    }
};
}
void companion(int client) {
    int listener=-1;
    try {
        Hello hello{};ucred peer{};socklen_t length=sizeof(peer);
        if(!transfer(client,&hello,sizeof(hello),false)||hello.version!=3||hello.hiddenCount>128||hello.uid%100000<10000||hello.uid%100000>19999)return;
        if(getsockopt(client,SOL_SOCKET,SO_PEERCRED,&peer,&length)||(peer.pid!=int(hello.pid)&&peer.uid!=0))return;
        Identity identity;if(!status(hello.tid,identity)||identity.tgid!=int(hello.pid)||(identity.uid!=0&&identity.uid!=int(hello.uid)))return;
        std::vector<uint32_t> hidden(hello.hiddenCount);
        if(!hidden.empty()&&!transfer(client,hidden.data(),hidden.size()*sizeof(uint32_t),false))return;
        for(auto uid:hidden)if(uid==hello.uid||uid/100000!=hello.uid/100000||uid%100000<10000||uid%100000>19999)return;
        Session session;if(!session.prepare(hello.tid,std::move(hidden)))return;
        char ready='R';if(!transfer(client,&ready,1,true))return;
        char byte=0;alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
        iovec payload{&byte,1};msghdr message{};message.msg_iov=&payload;message.msg_iovlen=1;
        message.msg_control=control;message.msg_controllen=sizeof(control);
        pollfd descriptor{client,POLLIN,0};int ready_count;
        do{ready_count=poll(&descriptor,1,-1);}while(ready_count<0&&errno==EINTR);
        if(ready_count<=0)return;
        ssize_t n;do{n=recvmsg(client,&message,MSG_CMSG_CLOEXEC);}while(n<0&&errno==EINTR);
        auto* header=CMSG_FIRSTHDR(&message);
        if(n!=1||!header||header->cmsg_level!=SOL_SOCKET||header->cmsg_type!=SCM_RIGHTS||header->cmsg_len!=CMSG_LEN(sizeof(int)))return;
        memcpy(&listener,CMSG_DATA(header),sizeof(listener));
        if(byte=='F'&&!(message.msg_flags&MSG_CTRUNC)) {
            // Custody is established before acknowledgment. Even if the client
            // loses this acknowledgment, keep servicing its installed filter.
            char attached='A';
            transfer(client,&attached,1,true);
            session.serve(listener);
        }
    }catch(...){ }
    if(listener>=0)close(listener);
}
}

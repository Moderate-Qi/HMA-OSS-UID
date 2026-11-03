// Independent behavioural probes, executed only in disposable host children.
#define main unused_policy_main
#include "policy_test.cpp"
#undef main
#include <atomic>
#include <thread>
#include <poll.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>

static void install(std::vector<sock_filter> code) {
    sock_fprog f{(unsigned short)code.size(),code.data()};
    require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0,"set host NNP");
    require(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&f)==0,"install probe policy");
}
static std::vector<sock_filter> host_rule() {
    auto rule=hma_uid::make_rule({0,49999});rule[1].k=AUDIT_ARCH_X86_64;rule[4].k=SYS_getpriority;return rule;
}
static int fd_count() {DIR* d=opendir("/proc/self/fd");require(d,"open fd list");int n=0;while(auto* e=readdir(d))if(e->d_name[0]!='.')++n;closedir(d);return n;}
static int status_value(int fd,const char* key) {
    char text[8192]{};lseek(fd,0,SEEK_SET);auto n=read(fd,text,sizeof(text)-1);require(n>0,"read status");
    auto* value=strstr(text,key);require(value,"status field");return atoi(value+strlen(key));
}
static void merged_status(bool candidate) {
    auto p=platform();
    if(candidate){sock_fprog f{(unsigned short)p.size(),p.data()};std::vector<sock_filter> m;require(uid_filter::detail::merge_with_budget(f,hma_uid::make_rule({10011}),m),"audit merge");p.swap(m);}
    for(auto& op:p)if(op.code==(BPF_JMP|BPF_JEQ|BPF_K)&&op.k==AUDIT_ARCH_AARCH64)op.k=AUDIT_ARCH_X86_64;
    int fd=open("/proc/self/status",O_RDONLY|O_CLOEXEC);require(fd>=0,"status fd");install(p);
    int nnp=status_value(fd,"NoNewPrivs:"), mode=status_value(fd,"Seccomp:"), filters=status_value(fd,"Seccomp_filters:");close(fd);
    printf("STATUS %s nnp=%d mode=%d filters=%d\n",candidate?"merged":"original",nnp,mode,filters);
}
static void surface(bool candidate) {
    int before=fd_count();int initial_nnp=prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0);
    if(candidate)install(host_rule());else install({sock_filter BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)});
    int after=fd_count();seccomp_notif_sizes sizes{};long s=syscall(SYS_seccomp,SECCOMP_GET_NOTIF_SIZES,0,&sizes);
    uint32_t action=SECCOMP_RET_USER_NOTIF;long a=syscall(SYS_seccomp,SECCOMP_GET_ACTION_AVAIL,0,&action);
    errno=0;long process=syscall(SYS_getpriority,PRIO_PROCESS,0);int pe=errno;
    errno=0;long absent=syscall(SYS_getpriority,PRIO_USER,49998);int ae=errno;
    errno=0;long hidden=syscall(SYS_getpriority,PRIO_USER,0);int he=errno;
    printf("SURFACE %s fd=%d/%d prior_nnp=%d notif_sizes=%ld:%u,%u,%u action=%ld process=%ld:%d absent=%ld:%d target=%ld:%d\n",candidate?"filtered":"original",before,after,initial_nnp,s,sizes.seccomp_notif,sizes.seccomp_notif_resp,sizes.seccomp_data,a,process,pe,absent,ae,hidden,he);
    std::atomic<long> threaded{-99};std::atomic<int> thread_errno{0};
    std::thread thread([&](){errno=0;threaded=syscall(SYS_getpriority,PRIO_USER,0);thread_errno=errno;});thread.join();
    printf("THREAD %s target=%ld:%d\n",candidate?"filtered":"original",threaded.load(),thread_errno.load());
    require(before==after && s==0 && a==0 && process>=0 && absent==-1 && ae==ESRCH,"unchanged normal surface");
    if(candidate)require(hidden==-1 && he==ESRCH && threaded==-1 && thread_errno==ESRCH,"main/thread UID hiding");
}
static void notification(bool candidate) {
    if(candidate)install(host_rule());else require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0,"notify NNP");
    sock_filter code[]={BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr)),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getpriority,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    sock_fprog filter{4,code};int listener=syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&filter);require(listener>=0,"app listener installation");
    std::atomic<long> result{-99};std::atomic<int> error{0};
    std::thread query([&](){errno=0;result=syscall(SYS_getpriority,PRIO_USER,0);error=errno;});
    pollfd p{listener,POLLIN,0};int ready=poll(&p,1,250);bool notified=false;
    if(ready>0 && (p.revents&POLLIN)) {
        seccomp_notif request{};require(ioctl(listener,SECCOMP_IOCTL_NOTIF_RECV,&request)==0,"receive app notification");
        seccomp_notif_resp response{};response.id=request.id;response.flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        require(ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&response)==0,"continue app notification");notified=true;
    }
    close(listener);query.join();
    printf("NOTIFICATION %s own_listener_notified=%d target=%ld:%d\n",candidate?"filtered":"original",notified,result.load(),error.load());
    require(candidate ? (!notified && result==-1 && error==ESRCH) : (notified && result>=0),"explicit notification-precedence result");
}
static void listener_collision(bool dynamic_reference) {
    require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0,"listener NNP");
    sock_filter allow=BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);sock_fprog f{1,&allow};int prior=-1;
    if(dynamic_reference){prior=syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&f);require(prior>=0,"reference listener");}else install(host_rule());
    errno=0;int app=syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&f);int error=errno;
    printf("LISTENER %s app_listener=%s errno=%d\n",dynamic_reference?"USER_NOTIF_reference":"static_candidate",app>=0?"accepted":"rejected",error);
    if(app>=0)close(app);if(prior>=0)close(prior);
}
static uint64_t now_ns(){timespec t{};clock_gettime(CLOCK_MONOTONIC_RAW,&t);return uint64_t(t.tv_sec)*1000000000ULL+t.tv_nsec;}
static void timing(bool candidate) {
    if(candidate)install(host_rule());else install({sock_filter BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)});
    std::vector<int64_t> differences,masked,control;
    for(int n=0;n<2200;++n){
        const int first=n%2?49999:49998,second=n%2?49998:49999;
        auto a=now_ns();syscall(SYS_getpriority,PRIO_USER,first);auto b=now_ns();
        auto c=now_ns();syscall(SYS_getpriority,PRIO_USER,second);auto d=now_ns();
        if(n>=200){int64_t hidden_time=n%2?b-a:d-c,control_time=n%2?d-c:b-a;masked.push_back(hidden_time);control.push_back(control_time);differences.push_back(hidden_time-control_time);}
    }
    std::sort(masked.begin(),masked.end());std::sort(control.begin(),control.end());std::sort(differences.begin(),differences.end());
    printf("TIMING %s paired=2000 hidden_median_ns=%ld control_median_ns=%ld paired_difference_ns=%ld\n",candidate?"filtered":"original",masked[1000],control[1000],differences[1000]);
}
int main(){
    for(int test=0;test<10;++test){
        pid_t pid=fork();require(pid>=0,"audit fork");
        if(!pid){bool candidate=test%2;
            if(test<2)merged_status(candidate);else if(test<4)surface(candidate);else if(test<6)notification(candidate);else if(test<8)listener_collision(candidate);else timing(candidate);
            fflush(stdout);_exit(0);
        }
        int status=0;require(waitpid(pid,&status,0)==pid && status==0,"audit child");
    }
    puts("PASS probes executed; NOTIFICATION and TIMING are residual observability, not an invisibility pass");
}

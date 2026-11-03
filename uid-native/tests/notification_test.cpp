#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include "../runtime/uid_notification.hpp"
#ifdef HMA_DUCK_RUNTIME_TEST
#include "seccomp_uid_protocol.h"
static int app_listener(){
    sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_getpriority,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PRIO_USER,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    sock_fprog p{8,code};return syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&p);
}
static int filter_count(){
    FILE* f=fopen("/proc/self/status","re");if(!f)return -1;
    char line[256];int n=-1;while(fgets(line,sizeof(line),f))if(sscanf(line,"Seccomp_filters: %d",&n)==1)break;
    fclose(f);return n;
}
#endif

static void check(bool ok,const char* what){if(!ok){fprintf(stderr,"FAIL %s errno=%d\n",what,errno);_exit(1);}}
static int query(int which,uint32_t who){errno=0;long r=syscall(__NR_getpriority,which,who);return r==-1?-errno:int(r);}
static bool install_action(uint32_t action,bool synchronized=false){
    sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_getpriority,0,1),
        BPF_STMT(BPF_RET|BPF_K,action),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    sock_fprog p{4,code};
    return synchronized?syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_TSYNC,&p)==0
        :prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p)==0;
}
static void client(int channel,int test){
    using namespace hma_uid::notification;
    check(prepare(channel,10050,{10011}),"companion ready before installation");
    check(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0,"host NNP");
    int listener=install(rule({10011}));check(listener>=0,"notification installation");
    check(send_listener(channel,listener)==Delivery::acknowledged,"listener custody acknowledged");
    close(listener);close(channel);
    check(query(PRIO_USER,10011)==-ESRCH,"hidden active UID");
    check(query(PRIO_USER,0)>=0,"visible active UID preserved");
    check(query(PRIO_PROCESS,0)>=0,"process priority preserved");
    if(test==0){
        std::atomic<int> result{0};std::thread t([&]{result=query(PRIO_USER,10011);});t.join();check(result==-ESRCH,"new thread inherits hiding");
    } else if(test==1){
        check(install_action(SECCOMP_RET_TRACE),"own TRACE installed");
        check(query(PRIO_USER,10011)==-ENOSYS,"hidden UID respects TRACE");
        check(query(PRIO_USER,0)==-ENOSYS,"visible UID respects TRACE");
    } else if(test==2){
        check(install_action(SECCOMP_RET_ERRNO|EACCES),"own ERRNO installed");
        check(query(PRIO_USER,10011)==-EACCES,"own higher-priority errno preserved");
    } else if(test==3){
        sock_filter bad=BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);sock_fprog p{0,&bad};
        check(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p)==-1&&errno==EINVAL,"invalid rule retains kernel rejection");
        check(query(PRIO_USER,10011)==-ESRCH,"invalid install does not corrupt tracking");
    } else if(test==4){
        std::atomic<int> thread_result{0};
        std::thread t([&]{check(install_action(SECCOMP_RET_TRACE),"worker TRACE");thread_result=query(PRIO_USER,10011);
            pid_t child=fork();check(child>=0,"fork from policy-bearing worker");
            if(!child)_exit(query(PRIO_USER,10011)==-ENOSYS?0:11);
            int status=0;check(waitpid(child,&status,0)==child&&status==0,"worker child inherited TRACE");});
        t.join();check(thread_result==-ENOSYS,"worker own policy");
        check(query(PRIO_USER,10011)==-ESRCH,"leader did not inherit worker-only policy");
    } else if(test==5){
        check(install_action(SECCOMP_RET_TRACE),"parent TRACE");
        pid_t child=fork();check(child>=0,"fork with inherited policy");
        if(!child)_exit(query(PRIO_USER,10011)==-ENOSYS?0:12);
        int status=0;check(waitpid(child,&status,0)==child&&status==0,"child TRACE return retained");
    } else if(test==6){
        check(install_action(SECCOMP_RET_ALLOW,true),"TSYNC allowed to reach kernel");
        check(query(PRIO_USER,10011)>=0,"unsupported TSYNC degrades to kernel behavior");
    } else if(test==7){
        sock_filter allow=BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);sock_fprog p{1,&allow};
        errno=0;int fd=syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&p);
        check(fd<0&&errno==EBUSY,"listener collision recorded as residual");
        check(query(PRIO_USER,10011)==-ESRCH,"failed extra listener did not corrupt hiding");
    } else if(test==8){
        check(install_action(SECCOMP_RET_LOG),"own LOG installed");
        check(query(PRIO_USER,10011)==-ESRCH,"LOG keeps UID privacy");
    } else if(test==9){
        check(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,1UL)==-1&&errno==EFAULT,"invalid program pointer keeps kernel EFAULT");
        check(query(PRIO_USER,10011)==-ESRCH,"invalid pointer leaves policy tracking intact");
#ifdef HMA_DUCK_RUNTIME_TEST
    } else if(test==10){
        using namespace duckdetector::dangerousapps::seccomp_uid;
        const auto before=std::chrono::steady_clock::now();
        auto r=run_probe(10000,19999);
        auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-before).count();
        printf("DUCK1093 native install=%d errno=%d queried=%d notified=%d self=%d outcome=%d error=%d elapsed_ms=%ld\n",r.install_status,r.install_error,r.queried,r.notified,r.self_notified,r.query_outcome,r.query_error,long(elapsed));fflush(stdout);
        check(r.install_status==kInstalled&&r.install_error==0&&r.queried==10000&&r.notified==10000&&r.self_notified==1&&r.query_outcome==kQueryComplete,"unmodified Duck 1093 native probe passed");
        check(query(PRIO_USER,10011)==-ESRCH,"original application UID privacy remains after probe child exits");
    } else if(test==11){
        int before=filter_count();int fd=app_listener();check(fd>=0,"supported listener exported");
        printf("RESIDUAL nested filter count before=%d after=%d (virtual policy not added to kernel stack)\n",before,filter_count());
        check(fcntl(fd,F_GETFD)&FD_CLOEXEC,"listener CLOEXEC");
        char path[64],link[128]{};snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
        check(readlink(path,link,sizeof(link)-1)>0&&strstr(link,"seccomp notify"),"real listener descriptor type");
        for(int mode=0;mode<4;++mode){
            std::atomic<int> got{-999};std::thread worker([&]{got=query(PRIO_USER,mode==1?0:10011);});
            pollfd ready{fd,POLLIN,0};check(poll(&ready,1,1000)>0&&(ready.revents&POLLIN),"listener readiness");
            seccomp_notif req{};check(ioctl(fd,SECCOMP_IOCTL_NOTIF_RECV,&req)==0,"compat receive");
            check(ioctl(fd,SECCOMP_IOCTL_NOTIF_ID_VALID,&req.id)==0,"pending notification ID valid");
            seccomp_notif_resp response{};response.id=req.id;
            response.flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;response.val=1;
            check(ioctl(fd,SECCOMP_IOCTL_NOTIF_SEND,&response)==-1&&errno==EINVAL,"invalid CONTINUE response rejected");
            response.val=0;
            if(mode==2){response.flags=0;response.error=-EACCES;}
            if(mode==3){response.flags=0;response.val=77;}
            check(ioctl(fd,SECCOMP_IOCTL_NOTIF_SEND,&response)==0,"compat send");worker.join();
            check(mode==0?got==-ESRCH:mode==1?got>=0:mode==2?got==-EACCES:got==77,"CONTINUE/value/error and hidden UID semantics");
            check(ioctl(fd,SECCOMP_IOCTL_NOTIF_ID_VALID,&req.id)==-1&&errno==ENOENT,"replied notification expires");
        }
        close(fd);
    } else if(test==12){
        int fd=app_listener();check(fd>=0,"first listener");
        check(app_listener()==-1&&errno==EBUSY,"second app listener retains native collision");
        int copy=fcntl(fd,F_DUPFD_CLOEXEC,0);check(copy>=0,"duplicate listener");close(fd);
        std::atomic<int> got{-999};std::thread worker([&]{got=query(PRIO_USER,10011);});
        seccomp_notif req{};check(ioctl(copy,SECCOMP_IOCTL_NOTIF_RECV,&req)==0,"duplicate descriptor receives");
        seccomp_notif_resp r{};r.id=req.id;r.val=88;check(ioctl(copy,SECCOMP_IOCTL_NOTIF_SEND,&r)==0,"duplicate descriptor sends");worker.join();check(got==88,"duplicate query result");
        close(copy);check(query(PRIO_USER,10011)==-ENOSYS,"closing final listener retains kernel no-listener semantics");
        fd=app_listener();check(fd>=0,"new listener allowed after previous closes");close(fd);
    } else if(test==13){
        int fd=app_listener();check(fd>=0,"blocking receive listener");
        std::thread receiver([&]{seccomp_notif req{};check(ioctl(fd,SECCOMP_IOCTL_NOTIF_RECV,&req)==0,"blocking receive before query");seccomp_notif_resp r{};r.id=req.id;r.val=93;check(ioctl(fd,SECCOMP_IOCTL_NOTIF_SEND,&r)==0,"blocking receiver reply");});
        usleep(10000);check(query(PRIO_USER,10011)==93,"pending receiver dispatched");receiver.join();close(fd);
    } else if(test==14){
        int fd=eventfd(0,EFD_CLOEXEC);check(fd>=0,"ordinary eventfd");seccomp_notif n{};
        check(ioctl(fd,SECCOMP_IOCTL_NOTIF_RECV,&n)==-1&&errno==ENOTTY,"unrelated fd ioctl kept in kernel");close(fd);
        sock_filter bad=BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);sock_fprog p{1,&bad};
        check(syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&p)==-1&&errno==EBUSY,"unsupported broader listener retains kernel result");
        check(syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,reinterpret_cast<void*>(1))==-1&&errno==EFAULT,"invalid listener program pointer");
        check(query(PRIO_USER,10011)==-ESRCH,"unsupported requests preserve UID hiding");
    } else if(test==15){
        int fd=app_listener();check(fd>=0,"ADDFD listener");int source=open("/dev/null",O_RDONLY|O_CLOEXEC);check(source>=0,"ADDFD source");
        std::atomic<int> got{-999};std::thread worker([&]{got=query(PRIO_USER,10011);});
        seccomp_notif req{};check(ioctl(fd,SECCOMP_IOCTL_NOTIF_RECV,&req)==0,"ADDFD pending query");
        seccomp_notif_addfd add{};add.id=req.id;add.srcfd=source;add.flags=SECCOMP_ADDFD_FLAG_SEND;add.newfd_flags=O_CLOEXEC;
        int injected=ioctl(fd,SECCOMP_IOCTL_NOTIF_ADDFD,&add);check(injected>=0,"ADDFD|SEND forwarded");worker.join();
        check(got==injected&&(fcntl(injected,F_GETFD)&FD_CLOEXEC),"ADDFD query completion and descriptor");close(injected);close(source);close(fd);
    } else if(test==16){
        int fd=app_listener();check(fd>=0,"close-pending listener");
        std::atomic<int> got{-999};std::thread worker([&]{got=query(PRIO_USER,10011);});
        seccomp_notif req{};check(ioctl(fd,SECCOMP_IOCTL_NOTIF_RECV,&req)==0,"query received before last close");
        close(fd);worker.join();check(got==-ENOSYS,"last close releases blocked query without hanging");
    } else if(test==17){
        using namespace duckdetector::dangerousapps::seccomp_uid;
        for(int n=0;n<10;++n){auto r=run_probe(10000,10099);printf("REPEAT %d install=%d errno=%d queried=%d notified=%d outcome=%d error=%d\n",n,r.install_status,r.install_error,r.queried,r.notified,r.query_outcome,r.query_error);fflush(stdout);check(r.install_status==kInstalled&&r.notified==100&&r.query_outcome==kQueryComplete,"repeated disposable probe releases helper/session resources");}
        check(query(PRIO_USER,10011)==-ESRCH,"UID privacy after repeated listener probes");
#endif
    }
    printf("PASS notify_case=%d\n",test);fflush(stdout);
}
int main(){
    check(getuid()==0,"run isolated host harness as root");
    int hold[2],ready[2];check(pipe(hold)==0&&pipe(ready)==0,"victim channels");
    pid_t victim=fork();check(victim>=0,"victim fork");
    if(!victim){close(hold[1]);close(ready[0]);check(setuid(10011)==0,"temporary active UID");char one=1;check(write(ready[1],&one,1)==1,"victim ready");close(ready[1]);char stop;read(hold[0],&stop,1);_exit(0);}
    close(hold[0]);close(ready[1]);char one=0;check(read(ready[0],&one,1)==1,"active UID ready");close(ready[0]);
    check(query(PRIO_USER,10011)>=0,"baseline active UID exists");
    const int tests=
#ifdef HMA_DUCK_RUNTIME_TEST
        18;
#else
        10;
#endif
    for(int test=0;test<tests;++test){
        int pair[2];check(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)==0,"session channel");
        pid_t child=fork();check(child>=0,"client fork");
        if(!child){close(pair[0]);close(hold[1]);
#ifdef HMA_DUCK_RUNTIME_TEST
            if(test>=10)check(setuid(10050)==0,"ordinary Android-style caller UID");
#endif
            client(pair[1],test);_exit(0);}
        close(pair[1]);
        // Android's zygote reaps app children independently of the companion.
        // Mirror that lifetime here; otherwise this test parent can retain a
        // zombie while synchronously waiting for its notification service.
        int status=0;pid_t reaped=-1;
        std::thread reaper([&]{reaped=waitpid(child,&status,0);});
        hma_uid::notification::companion(pair[0]);close(pair[0]);reaper.join();
        check(reaped==child&&status==0,"client completion");
    }
    close(hold[1]);int status=0;check(waitpid(victim,&status,0)==victim&&status==0,"victim completion");
    puts("PASS actual notification broker: selective hiding, TRACE/LOG/ERRNO, invalid rule, thread/child inheritance, TSYNC fail-open, listener residual");
}

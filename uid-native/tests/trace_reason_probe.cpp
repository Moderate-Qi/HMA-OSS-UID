// Diagnose static ERRNO precedence using the delivered merger and AOSP policy.
#define main unused_policy_main
#include "policy_test.cpp"
#undef main

static int run(bool candidate) {
    auto code=platform();
    if(candidate) {
        sock_fprog original{(unsigned short)code.size(),code.data()};std::vector<sock_filter> merged;
        require(uid_filter::detail::merge_with_budget(original,hma_uid::make_rule({10011}),merged),"trace probe merge");code.swap(merged);
    }
    for(size_t i=0;i+4<code.size();++i) {
        if(code[i].code==(BPF_LD|BPF_W|BPF_ABS)&&code[i].k==offsetof(seccomp_data,arch)&&code[i+1].k==AUDIT_ARCH_AARCH64) {
            code[i+1].k=AUDIT_ARCH_X86_64;
            if(i>0)code[i+4].k=SYS_getpriority;
        }
    }
    require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0,"host NNP");
    sock_fprog p{(unsigned short)code.size(),code.data()};
    require(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p)==0,"initial AOSP policy");
    sock_filter own[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getpriority,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    sock_fprog test{4,own};require(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&test)==0,"app TRACE rule");
    errno=0;long normal=syscall(SYS_getpriority,PRIO_USER,10012);int ne=errno;
    errno=0;long hidden=syscall(SYS_getpriority,PRIO_USER,10011);int he=errno;
    printf("TRACE %s visible_uid=%ld errno=%d hidden_uid=%ld errno=%d\n",candidate?"HMA-UID-1":"original",normal,ne,hidden,he);
    require(normal==-1&&ne==ENOSYS,"normal UID respects app TRACE");
    require(hidden==-1&&he==(candidate?ESRCH:ENOSYS),"observed hidden UID action precedence");
    return 0;
}
int main(){
    for(bool candidate:{false,true}){pid_t p=fork();require(p>=0,"fork");if(!p){int r=run(candidate);fflush(stdout);_exit(r);}int status=0;require(waitpid(p,&status,0)==p&&status==0,"trace child");}
    puts("CONFIRMED: candidate ERRNO masks app TRACE; baseline returns ENOSYS, candidate returns ESRCH for hidden UID");
}

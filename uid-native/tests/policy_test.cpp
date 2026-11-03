#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../runtime/uid_rule.hpp"
#include "../runtime/uid_policy_budget.hpp"
#include "../../../evidence/arm64_app_policy.cpp"
#include "../../../evidence/arm_app_policy.cpp"

static void require(bool condition, const char* message) {
    if (!condition) { fprintf(stderr, "FAIL %s\n", message); exit(1); }
}
static uint32_t evaluate(const std::vector<sock_filter>& code, const seccomp_data& data) {
    uint32_t a = 0, x = 0;
    for (size_t pc = 0; pc < code.size(); ++pc) {
        auto op = code[pc];
        if (op.code == (BPF_RET|BPF_K)) return op.k;
        if (op.code == (BPF_LD|BPF_W|BPF_ABS)) { require(op.k + 4 <= sizeof(data), "load bounds"); memcpy(&a, (char*)&data + op.k, 4); }
        else if (op.code == (BPF_LD|BPF_W|BPF_IMM)) a = op.k;
        else if (op.code == (BPF_MISC|BPF_TAX)) x = a;
        else if (op.code == (BPF_ALU|BPF_AND|BPF_K)) a &= op.k;
        else if (op.code == (BPF_ALU|BPF_RSH|BPF_K)) a >>= op.k;
        else if (op.code == (BPF_ALU|BPF_RSH|BPF_X)) a >>= (x & 31);
        else if (op.code == (BPF_JMP|BPF_JA)) pc += op.k;
        else if (BPF_CLASS(op.code) == BPF_JMP) {
            bool yes = false;
            switch (BPF_OP(op.code)) {
                case BPF_JEQ: yes = a == op.k; break;
                case BPF_JGE: yes = a >= op.k; break;
                case BPF_JGT: yes = a > op.k; break;
                case BPF_JSET: yes = (a & op.k) != 0; break;
                default: require(false, "unknown jump");
            }
            pc += yes ? op.jt : op.jf;
        } else require(false, "unknown instruction");
    }
    require(false, "unterminated policy"); return 0;
}
static std::vector<sock_filter> platform() {
    std::vector<sock_filter> p{
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_AARCH64, 2, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_ARM, 0, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, nr))};
    p.insert(p.end(), arm64_app_filter, arm64_app_filter + arm64_app_filter_size);
    p.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP));
    require(p.size() - 3 <= 255, "AOSP secondary jump"); p[2].jt = p.size() - 3;
    p.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, nr)));
    p.insert(p.end(), arm_app_filter, arm_app_filter + arm_app_filter_size);
    p.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP));
    return p;
}
static int kernel_probe() {
    // A host-only kernel test, using exactly the delivered rule with the host ABI/nr substituted.
    auto rule = hma_uid::make_rule({0}); rule[1].k = AUDIT_ARCH_X86_64; rule[4].k = SYS_getpriority;
    sock_fprog filter{(unsigned short)rule.size(), rule.data()};
    errno = 0; long baseline = syscall(SYS_getpriority, PRIO_USER, 0);
    if (baseline < 0) return 10;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)) return 11;
    errno = 0; long hidden = syscall(SYS_getpriority, PRIO_USER, 0);
    if (hidden != -1 || errno != ESRCH) return 12;
    if (syscall(SYS_getpriority, PRIO_PROCESS, 0) < 0) return 13;
    sock_filter notify_code[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_getpriority, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)};
    sock_fprog notify{4, notify_code};
    int listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &notify);
    if (listener < 0) return 14;
    errno = 0; hidden = syscall(SYS_getpriority, PRIO_USER, 0);
    if (hidden != -1 || errno != ESRCH) return 15;
    close(listener);
    return 0;
}
static size_t capacity_probe(std::vector<sock_filter> policy) {
    for (auto& op : policy) if (op.code == (BPF_JMP|BPF_JEQ|BPF_K) && op.k==AUDIT_ARCH_AARCH64) op.k=AUDIT_ARCH_X86_64;
    for (int nr : {1,157,231}) {
        seccomp_data d{}; d.arch=AUDIT_ARCH_X86_64;d.nr=nr;
        require(evaluate(policy,d)==SECCOMP_RET_ALLOW,"host capacity probe syscalls permitted");
    }
    int result_fd[2]; require(pipe(result_fd)==0,"pipe");
    pid_t child=fork();require(child>=0,"fork capacity");
    if (!child) {
        sock_filter fill[4096];for(auto& op:fill)op=BPF_STMT(BPF_LD|BPF_W|BPF_IMM,0);
        sock_fprog initial{(unsigned short)policy.size(),policy.data()};
        if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&initial))_exit(20);
        size_t installed=0;
        for(int length=4096;length>=1;length/=2) {
            fill[length-1]=BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
            sock_fprog f{(unsigned short)length,fill};
            while(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&f)==0) installed+=length;
            fill[length-1]=BPF_STMT(BPF_LD|BPF_W|BPF_IMM,0);
            if(errno!=ENOMEM)_exit(21);
        }
        if(write(result_fd[1],&installed,sizeof(installed))!=sizeof(installed))_exit(22);
        _exit(0);
    }
    int status=0;require(waitpid(child,&status,0)==child && status==0,"capacity child status");
    size_t result=0;require(read(result_fd[0],&result,sizeof(result))==sizeof(result),"capacity result");
    close(result_fd[0]);close(result_fd[1]);return result;
}
int main() {
    auto original = platform(); sock_fprog p{(unsigned short)original.size(), original.data()};
    size_t cases = 0, supported = 0;
    for (int count : {1, 2, 4, 8, 16, 24, 32, 64, 128}) {
        std::vector<uint32_t> hidden; for (int n=0;n<count;++n) hidden.push_back(10011+n*3);
        auto rule = hma_uid::make_rule(hidden); std::vector<sock_filter> merged;
        const bool ok = uid_filter::detail::merge_with_budget(p, rule, merged);
        printf("AOSP16 hidden=%d rule_cbpf=%zu rule_cost=%zu merge=%s\n",count,rule.size(),uid_filter::detail::converted_size(rule),ok?"yes":"skip");
        if (!ok) { require(merged.empty(), "unsupported policy left unchanged"); continue; }
        ++supported;
        require(merged.size() == original.size(), "classic budget retained");
        require(uid_filter::detail::converted_size(merged) == uid_filter::detail::converted_size(original), "converted budget retained");
        for (uint32_t arch : std::initializer_list<uint32_t>{AUDIT_ARCH_AARCH64, AUDIT_ARCH_ARM, AUDIT_ARCH_X86_64}) {
            for (uint32_t nr = 0; nr < 8192; ++nr) {
                seccomp_data d{}; d.arch=arch; d.nr=nr; d.args[0]=PRIO_USER; d.args[1]=hidden[0];
                auto before = evaluate(original,d); auto expected = before;
                if (arch == AUDIT_ARCH_AARCH64 && nr == 141 && before == SECCOMP_RET_ALLOW) expected = SECCOMP_RET_ERRNO|ESRCH;
                require(evaluate(merged,d)==expected, "syscall/compat behavior retained"); ++cases;
            }
        }
        for (uint32_t uid=0;uid<130000;++uid) for (int which : std::initializer_list<int>{-1,PRIO_PROCESS,PRIO_PGRP,PRIO_USER,3}) {
            seccomp_data d{};d.arch=AUDIT_ARCH_AARCH64;d.nr=141;d.args[0]=which;d.args[1]=uid;
            auto expected = which==PRIO_USER && std::find(hidden.begin(),hidden.end(),uid)!=hidden.end() ? SECCOMP_RET_ERRNO|ESRCH : SECCOMP_RET_ALLOW;
            require(evaluate(merged,d)==expected, "only configured getpriority UID affected"); ++cases;
        }
        for (uint32_t nr : {0x7fffffffU,0x80000000U,0xffffffffU}) {
            seccomp_data d{};d.arch=AUDIT_ARCH_ARM;d.nr=nr;
            require(evaluate(original,d)==evaluate(merged,d),"compat unsigned boundary"); ++cases;
        }
    }
    require(supported>0,"at least one fitting policy");
    auto unsupported=original;unsupported[1].k=AUDIT_ARCH_X86_64;
    sock_fprog u{(unsigned short)unsupported.size(),unsupported.data()};std::vector<sock_filter> output;
    require(!uid_filter::detail::merge_with_budget(u,hma_uid::make_rule({10011}),output),"unknown platform fail open");
    pid_t child=fork();require(child>=0,"fork");if(!child)_exit(kernel_probe());
    int status=0;require(waitpid(child,&status,0)==child,"waitpid");
    printf("HOST_KERNEL_TEST status=%d (0 validates ERRNO semantics and confirms deeper USER_NOTIF detectability)\n",status);
    require(status==0,"kernel probe");
    const size_t baseline_capacity=capacity_probe(original);
    for(int count:{1,16,32,64,128}) {
        std::vector<uint32_t> hidden;for(int n=0;n<count;++n)hidden.push_back(10011+n*3);
        std::vector<sock_filter> merged;
        if(!uid_filter::detail::merge_with_budget(p,hma_uid::make_rule(hidden),merged))continue;
        const size_t capacity=capacity_probe(merged);
        printf("HOST_CAPACITY hidden=%d original=%zu merged=%zu\n",count,baseline_capacity,capacity);
        require(capacity==baseline_capacity,"actual host kernel remaining capacity retained");
    }
    printf("PASS differential_cases=%zu original_cbpf=%zu original_converted=%zu supported_sizes=%zu\n",cases,original.size(),uid_filter::detail::converted_size(original),supported);
    return 0;
}

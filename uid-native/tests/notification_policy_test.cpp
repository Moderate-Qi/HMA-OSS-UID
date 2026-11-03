#define main unused_policy_test_main
#include "policy_test.cpp"
#undef main
#include "../runtime/uid_notification.hpp"
int main(){
    auto original=platform();sock_fprog p{(unsigned short)original.size(),original.data()};
    size_t cases=0,supported=0;
    const auto original_capacity=capacity_probe(original);
    for(int count:{1,2,16,32,64,128}){
        std::vector<uint32_t> hidden;for(int n=0;n<count;++n)hidden.push_back(10011+n*3);
        auto rule=hma_uid::notification::rule(hidden);
        // This is a virtual AArch64 differential test on an x86_64 host.
        rule[1].k=AUDIT_ARCH_AARCH64;rule[4].k=220;rule[5].k=435;rule[6].k=277;rule[7].k=167;
        rule[13].k=29;rule[22].k=141;
        std::vector<sock_filter> merged;
        const bool ok=uid_filter::detail::merge_with_budget(p,rule,merged);
        printf("NOTIFY_POLICY hidden=%d merge=%s\n",count,ok?"yes":"skip");
        if(!ok)continue;++supported;
        require(merged.size()==original.size()&&uid_filter::detail::converted_size(merged)==uid_filter::detail::converted_size(original),"both budgets retained");
        for(uint32_t arch:std::initializer_list<uint32_t>{AUDIT_ARCH_AARCH64,AUDIT_ARCH_ARM,AUDIT_ARCH_X86_64})
        for(int which:std::initializer_list<int>{PRIO_PROCESS,PRIO_USER,PR_SET_SECCOMP})
        for(uint32_t nr=0;nr<8192;++nr){
            seccomp_data d{};d.arch=arch;d.nr=nr;d.args[0]=which;d.args[1]=hidden[0];
            auto before=evaluate(original,d),expected=before;
            if(before==SECCOMP_RET_ALLOW&&arch==AUDIT_ARCH_AARCH64 &&
                (nr==220||nr==435||nr==277||(nr==167&&which==PR_SET_SECCOMP)||(nr==141&&which==PRIO_USER)))expected=SECCOMP_RET_USER_NOTIF;
            require(evaluate(merged,d)==expected,"notification scope across architecture/syscall");++cases;
        }
        for(uint32_t uid=0;uid<130000;++uid){
            seccomp_data d{};d.arch=AUDIT_ARCH_AARCH64;d.nr=141;d.args[0]=PRIO_USER;d.args[1]=uid;
            bool targeted=true; // Membership remains in the companion; visibility is forwarded.
            require(evaluate(merged,d)==(targeted?SECCOMP_RET_USER_NOTIF:SECCOMP_RET_ALLOW),"all PRIO_USER queries reach the selective companion");++cases;
        }
        for(uint32_t cmd:{uint32_t(SECCOMP_IOCTL_NOTIF_RECV),uint32_t(SECCOMP_IOCTL_NOTIF_SEND),uint32_t(SECCOMP_IOCTL_NOTIF_ID_VALID),uint32_t(SECCOMP_IOCTL_NOTIF_ADDFD),uint32_t(FIONREAD)}){
            seccomp_data d{};d.arch=AUDIT_ARCH_AARCH64;d.nr=29;d.args[1]=cmd;
            require(evaluate(merged,d)==(cmd==uint32_t(FIONREAD)?SECCOMP_RET_ALLOW:SECCOMP_RET_USER_NOTIF),"only notification ioctl commands delegated");++cases;
        }
        auto capacity=capacity_probe(merged);require(capacity==original_capacity,"actual kernel converted budget retained");
        printf("NOTIFY_CAPACITY hidden=%d original=%zu merged=%zu\n",count,original_capacity,capacity);
    }
    require(supported>=2,"common selected scopes fit without fallback");
    printf("PASS notification differential cases=%zu fitting_sizes=%zu\n",cases,supported);
}

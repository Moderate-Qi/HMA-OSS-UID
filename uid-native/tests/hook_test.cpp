// The delivered HmaUidFilter is linked unchanged; only Android/Zygisk services
// and the /data/misc fixture path are substituted by this host harness.
#define main unused_policy_test_main
#include "policy_test.cpp"
#undef main
#include "../runtime/uid_filter.hpp"
#include <dirent.h>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <string>

static std::string fixture;
extern "C" FILE* __real_fopen(const char*,const char*);
extern "C" DIR* __real_opendir(const char*);
static std::string mapped(const char* path) {
    std::string p(path); if(p.rfind("/data/misc",0)==0)p=fixture+p.substr(10);return p;
}
extern "C" FILE* __wrap_fopen(const char* path,const char* mode){return __real_fopen(mapped(path).c_str(),mode);}
extern "C" DIR* __wrap_opendir(const char* path){return __real_opendir(mapped(path).c_str());}
extern "C" int __system_property_get(const char*,char* output){strcpy(output,"1");return 1;}
extern "C" int __android_log_print(int,const char*,const char*,...){return 0;}
extern "C" bool _Z22set_app_seccomp_filterv(){return true;}
using Prctl=int(*)(int,unsigned long,unsigned long,unsigned long,unsigned long);
static std::vector<sock_filter> captured;
static int calls=0,reject=0;
static bool fail_commit=false;
static uint32_t process_flags=0;
static int original_prctl(int op,unsigned long mode,unsigned long pointer,unsigned long,unsigned long){
    ++calls;
    if(op==PR_SET_SECCOMP && mode==SECCOMP_MODE_FILTER){
        auto& p=*reinterpret_cast<sock_fprog*>(pointer);captured.assign(p.filter,p.filter+p.len);
        if(reject){--reject;errno=EINVAL;return -1;}
    }
    return 0;
}
static int competitor(int,unsigned long,unsigned long,unsigned long,unsigned long){return 7;}
static void* active=reinterpret_cast<void*>(original_prctl);
static void* pending=nullptr;
static zygisk::Api* test_api=nullptr;
class HarnessModule:public zygisk::ModuleBase{void onLoad(zygisk::Api* api,JNIEnv*)override{test_api=api;}};
static void write_text(const std::string& path,const std::string& value){std::ofstream file(path);file<<value;require(file.good(),"fixture write");}
static void setup(const std::string& contents){
    std::filesystem::create_directories(fixture+"/hide_my_applist_test/uid_scope/g1_1");
    std::ifstream boot("/proc/sys/kernel/random/boot_id");std::string id;boot>>id;
    write_text(fixture+"/hide_my_applist_test/uid_scope/active",id+" g1_1\n");
    write_text(fixture+"/hide_my_applist_test/uid_scope/g1_1/10050",contents);
    active=reinterpret_cast<void*>(original_prctl);pending=nullptr;calls=0;reject=0;captured.clear();fail_commit=false;process_flags=0;
}
int main(int argc,char** argv){
    require(argc==2,"fixture argument");fixture=argv[1];
    zygisk::internal::api_table table{};
    table.registerModule=[](auto*,auto*){return true;};
    table.getFlags=[](void*){return process_flags;};
    table.pltHookRegister=[](dev_t,ino_t,const char*,void* replacement,void** old){if(old)*old=active;pending=replacement;};
    table.pltHookCommit=[](){if(fail_commit)return false;if(pending)active=pending;pending=nullptr;return true;};
    zygisk::internal::entry_impl<HarnessModule>(&table,nullptr);
    const std::string valid="HMA_UID_3\n10050\n10011\n10077\n";
    auto original=platform();sock_fprog p{(unsigned short)original.size(),original.data()};
    setup(valid);
    {HmaUidFilter h;h.prepare(test_api,10050);require(active!=reinterpret_cast<void*>(original_prctl),"scoped startup hook installed");
        require(reinterpret_cast<Prctl>(active)(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,reinterpret_cast<unsigned long>(&p),0,0)==0,"merged install forwarded");
        require(calls==1 && !captured.empty(),"original platform installer called once");
        seccomp_data d{};d.arch=AUDIT_ARCH_AARCH64;d.nr=141;d.args[0]=PRIO_USER;d.args[1]=10011;
        require(evaluate(captured,d)==SECCOMP_RET_ALLOW,"missing companion keeps exact platform policy");
        require(h.finish() && active==reinterpret_cast<void*>(original_prctl),"temporary hook restored before unload");}
    setup(valid);
    {HmaUidFilter h;h.prepare(test_api,10051);require(h.finish() && active==reinterpret_cast<void*>(original_prctl),"unselected caller unchanged");}
    setup(valid);process_flags=zygisk::PROCESS_GRANTED_ROOT;
    {HmaUidFilter h;h.prepare(test_api,10050);require(h.finish() && active==reinterpret_cast<void*>(original_prctl),"root-granted debugging app unchanged");}
    setup("HMA_UID_3\n10050\n110011\n");
    {HmaUidFilter h;h.prepare(test_api,10050);require(h.finish() && active==reinterpret_cast<void*>(original_prctl),"cross-user rule rejected");}
    setup(valid);write_text(fixture+"/hide_my_applist_test/uid_scope/active","OFF\n");
    {HmaUidFilter h;h.prepare(test_api,10050);require(h.finish() && active==reinterpret_cast<void*>(original_prctl),"OFF bypasses startup hook");}
    setup(valid);
    {HmaUidFilter h;h.prepare(test_api,10050);reject=0;
        require(reinterpret_cast<Prctl>(active)(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,reinterpret_cast<unsigned long>(&p),0,0)==0,"unavailable companion falls back to original policy");
        require(calls==1 && captured.size()==original.size() && !memcmp(captured.data(),original.data(),original.size()*sizeof(sock_filter)),"fallback is exact platform policy");
        require(h.finish(),"fallback hook restored");}
    setup(valid);
    {HmaUidFilter h;h.prepare(test_api,10050);active=reinterpret_cast<void*>(competitor);
        require(!h.finish() && active==reinterpret_cast<void*>(competitor),"chained callback preserved; unload refused");}
    setup(valid);
    {HmaUidFilter h;h.prepare(test_api,10050);fail_commit=true;require(!h.finish(),"failed restore prevents unload");}
    printf("PASS actual native hook: scoped/OFF/cross-user/companion-unavailable/fallback/restoration/chaining/failed-restore\n");
}

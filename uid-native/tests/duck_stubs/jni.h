#pragma once
// Host-only JNI bridge types. No Java method is exercised by this native test.
#define JNIEXPORT
#define JNICALL
using jint=int;
using jsize=int;
using jobject=void*;
using jintArray=void*;
struct JNIEnv {
    jintArray NewIntArray(jsize){return nullptr;}
    void SetIntArrayRegion(jintArray,jsize,jsize,const jint*){}
};

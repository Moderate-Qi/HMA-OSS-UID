# 构建与发行

基准提交与增强版本见 `publication/UPSTREAM.json`。以下命令在仓库根目录运行；Windows 使用 `gradlew.bat`，Linux/macOS 使用 `./gradlew`。

获取子模块：

```sh
git submodule update --init --recursive
```

## HMA-OSS UID3.1

环境：JDK 21，Android SDK 37，Build Tools 36.0.0，NDK r27c，Python 3。将 `local.properties.example` 复制为本地 local.properties，并填入本机 SDK 与原签名配置。设置 `JAVA_HOME`、`ANDROID_HOME`、`ANDROID_NDK_HOME`。

构建顺序保留 backend → UID payload → manager 的依赖关系：

```sh
python build_uid_native.py
./gradlew :zygote:assembleRelease
python package_uid_payload.py
./gradlew :app:assembleRelease
python publication/manager-migration/build_helper.py
```

从原签名 keystore 导出公开 DER 证书：

```sh
keytool -exportcert -keystore /path/to/local-signing.jks -alias YOUR_ALIAS -file release-input/manager-cert.der
```

使用实际 APK 输出路径打包：

```sh
python publication/package_module.py --manager app/build/outputs/apk/release/HMA-OSS-175-UID3.1-release.apk --backend zygote/build/outputs/apk/release/zygote-release.apk --native uid-native/build/arm64-v8a.so --helper publication/manager-migration/dex/classes.dex --certificate release-input/manager-cert.der --output publication-output/HMA-OSS-175-UID3.1-arm64.zip
```

manager 与 backend 使用同一签名，backend 构建时生成的 Magic.java 记录该公开证书。打包入口核对 manager 内嵌 payload 与外部 DEX、SO 的一致性，生成安装器实际读取的资源校验表。签名验收使用 SDK 的 `apksigner verify --verbose --print-certs` 分别核对两个 APK。

`publication/manager-migration/HmaManagerMigration.java` 对应 helper.dex；迁移 shell 与模板资源一起保留。

# �����뷢��

��׼�ύ����ǿ�汾�� `publication/UPSTREAM.json`�����������ڲֿ��Ŀ¼���У�Windows ʹ�� `gradlew.bat`��Linux/macOS ʹ�� `./gradlew`��

��ȡ��ģ�飺

```sh
git submodule update --init --recursive
```

## HMA-OSS UID3.1

������JDK 21��Android SDK 37��Build Tools 36.0.0��NDK r27c��Python 3���� `local.properties.example` ����Ϊ���� local.properties�������뱾�� SDK ��ԭǩ�����á����� `JAVA_HOME`��`ANDROID_HOME`��`ANDROID_NDK_HOME`��

����˳���� backend �� UID payload �� manager ��������ϵ��

```sh
python build_uid_native.py
./gradlew :zygote:assembleRelease
python package_uid_payload.py
./gradlew :app:assembleRelease
python publication/manager-migration/build_helper.py
```

��ԭǩ�� keystore �������� DER ֤�飺

```sh
keytool -exportcert -keystore /path/to/local-signing.jks -alias YOUR_ALIAS -file release-input/manager-cert.der
```

ʹ��ʵ�� APK ���·�������

```sh
python publication/package_module.py --manager app/build/outputs/apk/release/HMA-OSS-5398de45-UID3.1-release.apk --backend zygote/build/outputs/apk/release/zygote-release.apk --native uid-native/build/arm64-v8a.so --helper publication/manager-migration/dex/classes.dex --certificate release-input/manager-cert.der --output publication-output/HMA-OSS-5398de45-UID3.1-arm64.zip
```

manager �� backend ʹ��ͬһǩ����backend ����ʱ���ɵ� Magic.java ��¼�ù���֤�顣�����ں˶� manager ��Ƕ payload ���ⲿ DEX��SO ��һ���ԣ����ɰ�װ��ʵ�ʶ�ȡ����ԴУ�����ǩ������ʹ�� SDK �� `apksigner verify --verbose --print-certs` �ֱ�˶����� APK��

`publication/manager-migration/HmaManagerMigration.java` ��Ӧ helper.dex��Ǩ�� shell ��ģ����Դһ������

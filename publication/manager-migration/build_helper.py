from pathlib import Path
import os,subprocess

W=Path(__file__).resolve().parent
JAVA=Path(os.environ['JAVA_HOME'])
SDK=Path(os.environ.get('ANDROID_HOME') or os.environ['ANDROID_SDK_ROOT'])
jar=SDK/'platforms/android-37.0/android.jar'
suffix='.exe' if os.name=='nt' else ''
d8=SDK/('build-tools/36.0.0/d8.bat' if os.name=='nt' else 'build-tools/36.0.0/d8')
for name in ('classes','dex'):(W/name).mkdir(exist_ok=True)
env=dict(os.environ,JAVA_HOME=str(JAVA),JAVA_TOOL_OPTIONS='-Dfile.encoding=UTF-8 -Dsun.stdout.encoding=UTF-8 -Dsun.stderr.encoding=UTF-8')
subprocess.run([JAVA/('bin/javac'+suffix),'-encoding','UTF-8','-source','8','-target','8','-cp',jar,'-d',W/'classes',W/'HmaManagerMigration.java'],env=env,check=True)
subprocess.run([d8,'--release','--min-api','29','--lib',jar,'--output',W/'dex',W/'classes/HmaManagerMigration.class'],env=env,check=True)
print('Built root installer helper; existing APK/backend/native payloads retained')

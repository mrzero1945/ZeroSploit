# JNI entry points are resolved by name at runtime -> never rename them.
-keepclasseswithmembernames class com.zerosploit.core.Native {
    native <methods>;
}
-keepclasseswithmembernames class * {
    native <methods>;
}
# The event sink is looked up by name (getMethodID "onEvent") from native code.
-keep interface com.zerosploit.core.Native$Cb { *; }
# Json.parse reflects over nothing, but the UI dispatches on raw string event
# names emitted by C++, so keep the string constants' owners intact.
-keepclassmembers class com.zerosploit.core.Engine$Listener { *; }

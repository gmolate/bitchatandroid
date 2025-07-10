# Proguard/R8 rules for BitChat Android

# --- General Optimizations & Best Practices ---
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    # public static *** w(...); # Keep warnings
    # public static *** e(...); # Keep errors
}

# Keep annotations used by libraries at runtime
-keepattributes *Annotation*

# Keep InnerClasses attribute for reflection on inner classes
-keepattributes InnerClasses

# Keep Signature attribute for generic types, needed by libraries like Gson
-keepattributes Signature

# --- Kotlin Specific ---
# Keep Kotlin metadata for reflection and other Kotlin features
-keepattributes Kotlin
-keep class kotlin.Metadata { *; }
# Keep companion objects
-keepclassmembers class * {
    public static ** Companion;
}
# Keep default arguments in functions
-keepclassmembers class * {
    public static synthetic ** Stub(java.lang.String, int, kotlin.jvm.internal.DefaultConstructorMarker);
}
# Keep suspend functions for coroutines
-keepclassmembers class ** {
    final kotlin.coroutines.Continuation * C;
}
-keepclassmembers class **$*COROUTINE$* {
    java.lang.Object L$*;
    int label;
    java.lang.Object result;
}
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepnames class kotlinx.coroutines.android.AndroidExceptionPreHandler {}


# --- BouncyCastle ---
# These rules are generally recommended for BouncyCastle to ensure all providers and algorithms are available.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# --- LZ4 (lz4-java) ---
# Replace 'net.jpountz.lz4' with the actual package name if different for your specific lz4-java version.
-keep class net.jpountz.lz4.** { *; }
-dontwarn net.jpountz.lz4.**

# --- Gson ---
# Keep model classes that are serialized/deserialized by Gson.
# Replace 'com.example.bitchat.models' with your actual model package(s).
-keep class com.example.bitchat.models.** { <fields>; } # Keep fields
-keep class com.example.bitchat.viewmodel.UiMessage { <fields>; } # If UiMessage is directly serialized

# If you use @SerializedName, the above might be sufficient.
# If not, and field names are critical (e.g. matching a specific JSON structure),
# you might need to be more explicit or use -keepnames for those classes.
# For generic type adapters (like for List<ChannelInfo>):
-keep class com.google.gson.reflect.TypeToken {*;}
-keep class * extends com.google.gson.reflect.TypeToken

# --- Jetpack DataStore ---
# DataStore typically doesn't require special rules if you're using generated preference keys
# and standard data types. If you use custom serializers with reflection, they might need rules.
# For Proto DataStore, you'd keep the generated proto classes.

# --- Jetpack Compose ---
# Standard Compose rules are usually handled by the Android Gradle Plugin and R8's default rules.
# If you encounter issues, consult official Compose documentation for Proguard.
# -keepclassmembers class * { @androidx.compose.runtime.Composable <methods>; }
# -keepclassmembers class * { @androidx.compose.runtime.Composable <fields>; }

# --- AndroidX Security (androidx.security:security-crypto) ---
# Usually doesn't require special rules for its typical usage (EncryptedSharedPreferences, EncryptedFile).

# --- Guava (for BloomFilter) ---
# Guava is a large library. If you only use BloomFilter, R8 should be good at stripping unused parts.
# If specific issues arise, you might need to keep certain classes related to BloomFilter.
# For now, no specific rules added, assuming R8 handles it.

# Add any other library-specific rules here if needed.

# Example for keeping a specific class and its members if it's accessed via reflection:
# -keep public class com.example.MyClassWithReflection {
#     public <fields>;
#     public <methods>;
# }

# Keep parcelable classes and their creators
-keep class * implements android.os.Parcelable {
  public static final android.os.Parcelable$Creator *;
}
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# Ensure to test your release builds thoroughly after enabling minification.
# These rules are a starting point and might need adjustments based on your specific code and libraries.

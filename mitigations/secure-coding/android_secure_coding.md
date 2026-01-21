# Android Secure Coding Guidelines

## 🛡️ Overview

This guide provides comprehensive secure coding guidelines for Android application development, aligned with OWASP MASVS requirements and Android security best practices.

## 🎯 MASVS Alignment

These guidelines directly address the following MASVS categories:
- **MASVS-STORAGE**: Secure data storage and privacy
- **MASVS-CRYPTO**: Cryptography implementation
- **MASVS-AUTH**: Authentication and session management  
- **MASVS-NETWORK**: Network communication security
- **MASVS-PLATFORM**: Platform interaction security
- **MASVS-CODE**: Code quality and build settings

---

## 📱 1. Data Storage Security

### 1.1 Use EncryptedSharedPreferences for Sensitive Data

#### ✅ SECURE Implementation
```java
// Using Android Jetpack Security
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

public class SecurePreferencesManager {
    private static final String PREFS_FILE = "secure_prefs";
    private SharedPreferences encryptedPrefs;
    
    public SecurePreferencesManager(Context context) {
        try {
            MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
            
            encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                PREFS_FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
        } catch (GeneralSecurityException | IOException e) {
            // Handle encryption setup failure
            Log.e("Security", "Failed to create encrypted preferences", e);
        }
    }
    
    public void saveAuthToken(String token) {
        if (encryptedPrefs != null) {
            encryptedPrefs.edit()
                .putString("auth_token", token)
                .apply();
        }
    }
}
```

#### ❌ VULNERABLE Implementation
```java
// NEVER DO THIS - Plain text sensitive data
public class VulnerablePreferences {
    public void saveCredentials(Context context, String username, String password) {
        SharedPreferences prefs = context.getSharedPreferences("user_prefs", Context.MODE_PRIVATE);
        prefs.edit()
            .putString("username", username)
            .putString("password", password) // Plain text password!
            .apply();
    }
}
```

### 1.2 Database Encryption

#### ✅ SECURE SQLite Implementation
```java
// Using SQLCipher for database encryption
public class SecureDatabase extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "secure_app.db";
    private static final int DATABASE_VERSION = 1;
    
    public SecureDatabase(Context context, String password) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        SQLiteDatabase.loadLibs(context);
    }
    
    public SQLiteDatabase getWritableDatabase(String password) {
        return SQLiteDatabase.openOrCreateDatabase(
            getDatabasePath(), password, null, null);
    }
    
    public void insertSensitiveData(String data, String password) {
        SQLiteDatabase db = getWritableDatabase(password);
        ContentValues values = new ContentValues();
        values.put("sensitive_column", data);
        
        db.insert("sensitive_table", null, values);
        db.close();
    }
}
```

### 1.3 File Storage Security

#### ✅ SECURE File Storage
```java
public class SecureFileManager {
    private static final String ENCRYPTED_FILE_PREFIX = "secure_";
    
    public void saveSecureFile(Context context, String filename, byte[] data) {
        try {
            // Use internal storage (private to app)
            File internalFile = new File(context.getFilesDir(), ENCRYPTED_FILE_PREFIX + filename);
            
            // Encrypt data before saving
            byte[] encryptedData = encryptData(data);
            
            try (FileOutputStream fos = new FileOutputStream(internalFile)) {
                fos.write(encryptedData);
            }
            
            // Set restrictive permissions
            internalFile.setReadable(true, true);  // Owner only
            internalFile.setWritable(true, true);  // Owner only
            
        } catch (IOException e) {
            Log.e("Security", "Failed to save secure file", e);
        }
    }
    
    private byte[] encryptData(byte[] data) {
        // Implement AES-GCM encryption
        // Use Android Keystore for key management
        return data; // Simplified for example
    }
}
```

#### ❌ VULNERABLE File Storage
```java
// NEVER DO THIS - External storage without encryption
public class VulnerableFileStorage {
    public void saveFile(String filename, String sensitiveData) {
        File externalFile = new File(Environment.getExternalStorageDirectory(), filename);
        try (FileWriter writer = new FileWriter(externalFile)) {
            writer.write(sensitiveData); // Plain text on external storage!
        } catch (IOException e) {
            Log.e("Error", "Failed to write file", e);
        }
    }
}
```

---

## 🔐 2. Authentication and Session Management

### 2.1 Biometric Authentication

#### ✅ SECURE Biometric Implementation
```java
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricManager;

public class SecureBiometricAuth extends AppCompatActivity {
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;
    
    private void setupBiometricAuth() {
        BiometricManager biometricManager = BiometricManager.from(this);
        
        switch (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                Log.d("Auth", "App can authenticate using biometrics.");
                initializeBiometricPrompt();
                break;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                Log.e("Auth", "No biometric features available on this device.");
                fallbackToPassword();
                break;
            // Handle other cases...
        }
    }
    
    private void initializeBiometricPrompt() {
        Executor executor = ContextCompat.getMainExecutor(this);
        
        biometricPrompt = new BiometricPrompt(this, executor, 
            new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    // Handle authentication error
                    handleAuthenticationFailure();
                }
                
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    // User authenticated successfully
                    handleAuthenticationSuccess();
                }
                
                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    // Authentication failed but user can try again
                    showRetryMessage();
                }
            });
            
        promptInfo = new BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Use account password")
            .setConfirmationRequired(true)
            .build();
    }
    
    private void authenticate() {
        biometricPrompt.authenticate(promptInfo);
    }
}
```

### 2.2 Secure Session Management

#### ✅ SECURE Session Implementation
```java
public class SecureSessionManager {
    private static final String SESSION_TOKEN_KEY = "session_token";
    private static final String SESSION_EXPIRY_KEY = "session_expiry";
    private static final long SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
    
    private EncryptedSharedPreferences encryptedPrefs;
    
    public boolean isSessionValid() {
        String token = encryptedPrefs.getString(SESSION_TOKEN_KEY, null);
        long expiry = encryptedPrefs.getLong(SESSION_EXPIRY_KEY, 0);
        
        if (token == null || System.currentTimeMillis() > expiry) {
            clearSession();
            return false;
        }
        
        // Validate token with server
        return validateTokenWithServer(token);
    }
    
    public void createSession(String authToken) {
        long expiryTime = System.currentTimeMillis() + SESSION_TIMEOUT;
        
        encryptedPrefs.edit()
            .putString(SESSION_TOKEN_KEY, authToken)
            .putLong(SESSION_EXPIRY_KEY, expiryTime)
            .apply();
    }
    
    public void clearSession() {
        encryptedPrefs.edit()
            .remove(SESSION_TOKEN_KEY)
            .remove(SESSION_EXPIRY_KEY)
            .apply();
    }
    
    public void refreshSession() {
        if (isSessionValid()) {
            long newExpiry = System.currentTimeMillis() + SESSION_TIMEOUT;
            encryptedPrefs.edit()
                .putLong(SESSION_EXPIRY_KEY, newExpiry)
                .apply();
        }
    }
}
```

---

## 🌐 3. Network Security

### 3.1 Network Security Configuration

#### ✅ SECURE Network Config (`res/xml/network_security_config.xml`)
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Production configuration -->
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.yourapp.com</domain>
        <pin-set expiration="2025-12-31">
            <!-- SHA256 hash of your certificate's public key -->
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <!-- Backup pin for key rotation -->
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
    
    <!-- Debug configuration (only for debug builds) -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
            <certificates src="system"/>
        </trust-anchors>
    </debug-overrides>
    
    <!-- Base configuration for all other domains -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
</network-security-config>
```

#### AndroidManifest.xml Configuration
```xml
<application
    android:name=".MyApplication"
    android:networkSecurityConfig="@xml/network_security_config"
    android:allowBackup="false"
    android:debuggable="false">
    <!-- Rest of application configuration -->
</application>
```

### 3.2 HTTP Client Security

#### ✅ SECURE HTTP Client
```java
import okhttp3.*;
import javax.net.ssl.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SecureHttpClient {
    private static final String API_BASE_URL = "https://api.yourapp.com";
    private OkHttpClient client;
    
    public SecureHttpClient() {
        setupSecureClient();
    }
    
    private void setupSecureClient() {
        // Certificate pinning
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
            .add("api.yourapp.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.yourapp.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build();
        
        // Connection timeout and security settings
        client = new OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .addInterceptor(new AuthenticationInterceptor())
            .addInterceptor(new LoggingInterceptor())
            .build();
    }
    
    private class AuthenticationInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request originalRequest = chain.request();
            
            // Add authentication header
            Request.Builder builder = originalRequest.newBuilder()
                .header("Authorization", "Bearer " + getAuthToken())
                .header("User-Agent", getUserAgent());
            
            return chain.proceed(builder.build());
        }
    }
    
    public void makeSecureRequest(String endpoint, Callback callback) {
        Request request = new Request.Builder()
            .url(API_BASE_URL + endpoint)
            .build();
            
        client.newCall(request).enqueue(callback);
    }
}
```

---

## 🔧 4. Component Security

### 4.1 Activity and Intent Security

#### ✅ SECURE Activity Configuration
```xml
<!-- Secure Activity in AndroidManifest.xml -->
<activity
    android:name=".SecureActivity"
    android:exported="false"
    android:launchMode="singleTask"
    android:taskAffinity=""
    android:excludeFromRecents="true"
    android:screenOrientation="portrait">
    
    <!-- Only accept intents from trusted sources -->
    <intent-filter>
        <action android:name="com.yourapp.SECURE_ACTION"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="yourapp"
              android:host="secure"/>
    </intent-filter>
</activity>
```

#### ✅ SECURE Intent Handling
```java
public class SecureActivity extends AppCompatActivity {
    private static final String ALLOWED_PACKAGE = "com.yourapp.trusted";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        if (!isIntentSafe(getIntent())) {
            Log.w("Security", "Unsafe intent received, finishing activity");
            finish();
            return;
        }
        
        handleSecureIntent(getIntent());
    }
    
    private boolean isIntentSafe(Intent intent) {
        // Verify intent source
        if (intent == null) return false;
        
        // Check for dangerous extras
        Bundle extras = intent.getExtras();
        if (extras != null) {
            // Validate all extra data
            return validateIntentExtras(extras);
        }
        
        return true;
    }
    
    private boolean validateIntentExtras(Bundle extras) {
        // Implement validation logic for intent extras
        for (String key : extras.keySet()) {
            Object value = extras.get(key);
            if (!isValidExtraValue(key, value)) {
                return false;
            }
        }
        return true;
    }
    
    private void sendSecureIntent(Context context, String data) {
        Intent intent = new Intent("com.yourapp.SECURE_ACTION");
        intent.setPackage(context.getPackageName()); // Explicit package
        intent.putExtra("secure_data", data);
        
        // Verify receiver exists
        if (intent.resolveActivity(getPackageManager()) != null) {
            startActivity(intent);
        }
    }
}
```

### 4.2 Service Security

#### ✅ SECURE Service Implementation
```java
public class SecureService extends Service {
    private static final String REQUIRED_PERMISSION = "com.yourapp.permission.ACCESS_SECURE_SERVICE";
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Verify caller permissions
        if (!hasRequiredPermission()) {
            Log.w("Security", "Unauthorized access attempt to secure service");
            stopSelf();
            return START_NOT_STICKY;
        }
        
        // Validate intent data
        if (!isIntentValid(intent)) {
            Log.w("Security", "Invalid intent received");
            stopSelf();
            return START_NOT_STICKY;
        }
        
        // Process secure request
        processSecureRequest(intent);
        return START_NOT_STICKY;
    }
    
    private boolean hasRequiredPermission() {
        return checkCallingPermission(REQUIRED_PERMISSION) == PackageManager.PERMISSION_GRANTED;
    }
    
    private boolean isIntentValid(Intent intent) {
        // Implement intent validation logic
        return intent != null && intent.hasExtra("required_param");
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return null; // No binding interface
    }
}
```

---

## 🔑 5. Cryptography Implementation

### 5.1 Android Keystore Usage

#### ✅ SECURE Key Generation and Usage
```java
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;

public class AndroidKeystoreManager {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "MySecretKey";
    
    public void generateSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
            
            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationTimeout(30) // 30 seconds
                .setRandomizedEncryptionRequired(true)
                .build();
                
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();
            
        } catch (Exception e) {
            Log.e("Crypto", "Failed to generate key", e);
        }
    }
    
    public byte[] encryptData(String plaintext) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
            
            Cipher cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/" + 
                KeyProperties.BLOCK_MODE_GCM + "/" + 
                KeyProperties.ENCRYPTION_PADDING_NONE);
                
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            byte[] encryptedData = cipher.doFinal(plaintext.getBytes());
            byte[] iv = cipher.getIV();
            
            // Combine IV and encrypted data
            byte[] result = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);
            
            return result;
            
        } catch (Exception e) {
            Log.e("Crypto", "Encryption failed", e);
            return null;
        }
    }
}
```

---

## 📋 6. Build Security Configuration

### 6.1 ProGuard/R8 Security Configuration

#### ✅ SECURE ProGuard Rules (`proguard-rules.pro`)
```proguard
# Obfuscate all code
-dontskipnonpubliclibraryclasses
-dontpreverify
-verbose

# Remove logging in release builds
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
}

# Protect sensitive classes from reflection
-keep class com.yourapp.security.** { *; }
-keep class com.yourapp.crypto.** { *; }

# Remove debug information
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# Anti-tampering - make reverse engineering harder
-repackageclasses ''
-allowaccessmodification
-overloadaggressively
```

### 6.2 Gradle Build Security

#### ✅ SECURE build.gradle Configuration
```gradle
android {
    compileSdkVersion 34
    
    defaultConfig {
        applicationId "com.yourapp.secure"
        minSdkVersion 23 // Minimum for modern security features
        targetSdkVersion 34
        
        // Security configurations
        multiDexEnabled true
        resConfigs "en" // Reduce APK size, limit attack surface
    }
    
    buildTypes {
        debug {
            debuggable true
            minifyEnabled false
            shrinkResources false
            applicationIdSuffix ".debug"
            versionNameSuffix "-debug"
        }
        
        release {
            debuggable false
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
            
            // Security hardening
            crunchPngs true
            zipAlignEnabled true
        }
    }
    
    // Security-focused lint checks
    lintOptions {
        checkReleaseBuilds true
        abortOnError true
        warningsAsErrors true
        
        // Security-specific checks
        check 'Security'
        check 'TrustAllX509TrustManager'
        check 'BadHostnameVerifier'
        check 'InsecureBaseConfiguration'
    }
    
    // Signing configuration (use separate signing.gradle)
    signingConfigs {
        release {
            // Configure in separate gradle file for security
        }
    }
}

dependencies {
    // Security libraries
    implementation 'androidx.security:security-crypto:1.1.0-alpha06'
    implementation 'androidx.biometric:biometric:1.1.0'
    
    // Network security
    implementation 'com.squareup.okhttp3:okhttp:4.10.0'
    
    // Static analysis
    implementation 'com.jakewharton.timber:timber:5.0.1' // Secure logging
    
    // Testing
    testImplementation 'junit:junit:4.13.2'
    androidTestImplementation 'androidx.test.ext:junit:1.1.5'
}
```

---

## ✅ 7. Security Testing Integration

### 7.1 Unit Testing for Security

#### ✅ Security Unit Tests
```java
public class SecurityTest {
    
    @Test
    public void testPasswordValidation() {
        PasswordValidator validator = new PasswordValidator();
        
        // Test weak passwords
        assertFalse(validator.isValid("123456"));
        assertFalse(validator.isValid("password"));
        assertFalse(validator.isValid("abc123"));
        
        // Test strong passwords
        assertTrue(validator.isValid("MyStr0ngP@ssw0rd!"));
        assertTrue(validator.isValid("C0mpl3x#P@ssw0rd123"));
    }
    
    @Test
    public void testInputSanitization() {
        InputSanitizer sanitizer = new InputSanitizer();
        
        // Test SQL injection attempts
        String maliciousInput = "'; DROP TABLE users; --";
        String sanitized = sanitizer.sanitize(maliciousInput);
        assertFalse(sanitized.contains("DROP TABLE"));
        
        // Test XSS attempts  
        String xssInput = "<script>alert('xss')</script>";
        String sanitizedXss = sanitizer.sanitize(xssInput);
        assertFalse(sanitizedXss.contains("<script>"));
    }
    
    @Test
    public void testEncryptionDecryption() {
        SecureStorage storage = new SecureStorage(context);
        String originalData = "sensitive information";
        
        // Test encryption
        String encrypted = storage.encrypt(originalData);
        assertNotEquals(originalData, encrypted);
        
        // Test decryption
        String decrypted = storage.decrypt(encrypted);
        assertEquals(originalData, decrypted);
    }
}
```

---

## 📊 8. Security Monitoring and Logging

### 8.1 Secure Logging Implementation

#### ✅ SECURE Logging
```java
import timber.log.Timber;

public class SecureLogger {
    private static final boolean ENABLE_LOGGING = BuildConfig.DEBUG;
    
    public static void init() {
        if (ENABLE_LOGGING) {
            Timber.plant(new Timber.DebugTree());
        } else {
            // Production: no logging or secure logging only
            Timber.plant(new ProductionTree());
        }
    }
    
    public static void logSecurityEvent(String event, Object... args) {
        // Always log security events (sanitized)
        String sanitizedMessage = sanitizeLogMessage(event);
        Timber.i("SECURITY: " + sanitizedMessage, args);
        
        // Send to security monitoring system
        SecurityMonitor.reportEvent(sanitizedMessage);
    }
    
    private static String sanitizeLogMessage(String message) {
        // Remove sensitive data from log messages
        return message.replaceAll("password=\\w+", "password=***")
                     .replaceAll("token=\\w+", "token=***")
                     .replaceAll("\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b", "****-****-****-****");
    }
    
    private static class ProductionTree extends Timber.Tree {
        @Override
        protected void log(int priority, String tag, String message, Throwable t) {
            // Only log warnings and errors in production
            if (priority >= Log.WARN) {
                // Send to crash reporting service (without sensitive data)
                CrashReporting.log(priority, tag, sanitizeLogMessage(message), t);
            }
        }
    }
}
```

---

## 🔍 9. Security Code Review Checklist

### Android-Specific Security Checklist

#### Data Protection
- [ ] Sensitive data encrypted using EncryptedSharedPreferences
- [ ] Database encryption implemented for sensitive data
- [ ] No hardcoded secrets in code
- [ ] Proper file permissions set for sensitive files
- [ ] External storage avoided for sensitive data

#### Authentication & Authorization
- [ ] Strong authentication mechanisms implemented
- [ ] Biometric authentication properly configured
- [ ] Session management includes timeout and validation
- [ ] No credentials stored in plain text
- [ ] Multi-factor authentication implemented where required

#### Network Security
- [ ] HTTPS enforced for all network communications
- [ ] Certificate pinning implemented
- [ ] Network Security Configuration properly configured
- [ ] No cleartext traffic permitted in production
- [ ] Proper SSL/TLS validation

#### Component Security  
- [ ] Activities not unnecessarily exported
- [ ] Intent filters properly configured
- [ ] Dangerous permissions justified and minimized
- [ ] Services properly protected with permissions
- [ ] Broadcast receivers secured against intent hijacking

#### Cryptography
- [ ] Strong cryptographic algorithms used (AES-256, RSA-2048+)
- [ ] Android Keystore used for key management
- [ ] Proper random number generation (SecureRandom)
- [ ] No weak or deprecated algorithms
- [ ] Proper IV/salt generation and management

#### Code Quality
- [ ] Input validation implemented for all user inputs
- [ ] Output encoding prevents injection attacks
- [ ] Error handling doesn't leak sensitive information
- [ ] Debug information removed from release builds
- [ ] Code obfuscation enabled for sensitive applications

#### Build Security
- [ ] ProGuard/R8 configured to remove debug information
- [ ] Debug builds not deployed to production
- [ ] Signing configuration properly secured
- [ ] Dependencies regularly updated for security patches
- [ ] Static analysis tools integrated in build process

---

## 📚 Additional Resources

### Official Documentation
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [Android App Bundle Security](https://developer.android.com/guide/app-bundle/app-signing)
- [Network Security Configuration](https://developer.android.com/training/articles/security-config)

### Security Libraries
- [Android Jetpack Security](https://developer.android.com/jetpack/androidx/releases/security)
- [SQLCipher for Android](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/)
- [Conscrypt (BoringSSL for Android)](https://github.com/google/conscrypt)

### Testing Tools
- [OWASP ZAP](https://www.zaproxy.org/)
- [MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [QARK (Quick Android Review Kit)](https://github.com/linkedin/qark)

---

**Remember**: Security is an ongoing process. Regularly review and update your security practices as threats and technologies evolve.
# password-security-analyzer (Java)

Maven Central: `io.github.erendemirel:password-security-analyzer`

```xml
<dependency>
  <groupId>io.github.erendemirel</groupId>
  <artifactId>password-security-analyzer</artifactId>
  <version>0.1.0</version>
</dependency>
```

```java
System.out.println(
  com.psa.PasswordSecurityAnalyzer.analyzeOffline("password", null).get("label"));
```

Advisory only — see [root README](../../README.md#security-notice-server-side-use).

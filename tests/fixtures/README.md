# Test fixtures

| File | What it is |
| --- | --- |
| `hello.exe` | A small unsigned x64 PE ("hello world"), taken from [Le-Syl21/ssign](https://github.com/Le-Syl21/ssign) (`ssign-core/tests/fixtures/hello.exe`, MIT). Its Authenticode SHA-256 as computed by osslsigncode is `BC17B1C98515D63F366BCD9F472054AE49CD5E839043265CE060B38B33CA2A43`; the tests pin that value. |
| `hello-signtool.exe` | The same image signed with Microsoft `signtool` (Windows SDK 10.0.28000) on 2026-09-08 using a throwaway self-signed certificate (`CN=SSS signtool cross-check`, private key discarded) and a **real** Certum RFC 3161 timestamp (`/tr http://time.certum.pl /td sha256 /fd sha256`). It lets the verifier be tested against Microsoft's implementation and against a genuine Certum timestamp token, offline. |

No private key is stored in this repository; the tests generate fresh keys on every run.

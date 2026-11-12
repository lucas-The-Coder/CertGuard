# CertGuard

Check a TLS certificate for expiry and self signed issues. Backend only, C# console app.

Connects to a host on TLS, grabs the certificate, checks expiry date, days left, and if subject equals issuer, and reports a status and risk level for SOC triage.

## Features

- Async TLS connect with `TcpClient` and `SslStream`
- Grabs cert even if expired or self signed, to inspect it
- Checks expiry with `DateTime.UtcNow` and `NotAfter`
- Checks days left, flags if less than 30 days
- Checks self signed by comparing subject and issuer
- Handles empty host, bad port, and non existent host without crash
- No printing inside helpers, only `Main` prints

## Project Structure

- `Program.cs` - Main app, all 4 methods
- `CertGuard.csproj` - Project file, .NET 8.0, Nullable enabled

## How to Run

```bash
dotnet run -- <host> [port]
dotnet run -- google.com
dotnet run -- google.com 443
dotnet run

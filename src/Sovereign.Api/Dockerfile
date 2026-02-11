FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY src/Sovereign.Core/ Sovereign.Core/
COPY src/Sovereign.Crypto/ Sovereign.Crypto/
COPY src/Sovereign.Recovery/ Sovereign.Recovery/
COPY src/Sovereign.Verify/ Sovereign.Verify/
COPY src/Sovereign.Integrity/ Sovereign.Integrity/
COPY src/Sovereign.Api/ Sovereign.Api/

RUN dotnet publish Sovereign.Api/Sovereign.Api.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app .

ENV ASPNETCORE_URLS=http://+:8080
ENV SOVEREIGN_PROVIDER=local

EXPOSE 8080
ENTRYPOINT ["dotnet", "Sovereign.Api.dll"]

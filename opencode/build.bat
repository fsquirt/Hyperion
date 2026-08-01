del bun.lock
bun install
cd packages\opencode
bun run build --single --skip-embed-web-ui
copy ..\..\run-agent.bat dist\opencode-windows-x64\bin
copy ..\..\run-agent.ps1 dist\opencode-windows-x64\bin
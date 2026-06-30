#!/bin/sh
# Start OWASP Benchmark on Tomcat with Immunity IAST agent (iast-tool/agent.jar).
# Download agent first — see security/local-debug.sh or CI workflow.

set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AGENT="${ROOT}/iast-tool/agent.jar"

if [ ! -s "$AGENT" ]; then
  echo "Missing ${AGENT}"
  echo "Run security/local-debug.sh or download agent from management-server into iast-tool/agent.jar"
  exit 1
fi

case "$1" in
-q|--quiet) quiet="-D-Dorg.owasp.esapi.logSpecial.discard=true"; shift ;;
*)          quiet="" ;;
esac

cd "$ROOT"
echo "Starting Benchmark with Immunity IAST agent: ${AGENT}"
echo "When Tomcat is up, run ./runCrawler.sh in another terminal."
echo "Press Ctrl+C here to stop the server."
mvn ${quiet} initialize
exec mvn ${quiet} clean package cargo:run -Pdeploywimmunity

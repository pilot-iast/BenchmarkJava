#!/usr/bin/env bash
# Local IAST + OWASP crawler loop (no CI). Reads secrets from security/.env.local
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ROOT}/security/.env.local"
AGENT_JAR="${ROOT}/iast-tool/agent.jar"
SERVER_LOG="${ROOT}/benchmark-server.log"
SERVER_PID="${ROOT}/benchmark-server.pid"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a && source "$ENV_FILE" && set +a
fi

: "${IAST_SERVER_URL:?Set IAST_SERVER_URL in security/.env.local}"
: "${IAST_TOKEN:?Set IAST_TOKEN in security/.env.local}"
: "${PANEL_URL:?Set PANEL_URL in security/.env.local}"
: "${PANEL_USER:?Set PANEL_USER in security/.env.local}"
: "${PANEL_PASS:?Set PANEL_PASS in security/.env.local}"

IAST_PROJECT_NAME="${IAST_PROJECT_NAME:-benchmarkjava}"
IAST_TEMPLATE_ID="${IAST_TEMPLATE_ID:-2}"
BENCHMARK_BASE_URL="${BENCHMARK_BASE_URL:-https://127.0.0.1:8443/benchmark}"
VERSION="local-$(date +%s)"
SERVER="${IAST_SERVER_URL%/}"

cleanup() {
  if [[ -f "$SERVER_PID" ]]; then
    kill "$(cat "$SERVER_PID")" 2>/dev/null || true
  fi
  pkill -f 'cargo:run' 2>/dev/null || true
  pkill -f 'org.apache.catalina.startup.Bootstrap' 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Download agent (${SERVER}, project=${IAST_PROJECT_NAME}, version=${VERSION})"
mkdir -p "${ROOT}/iast-tool"
curl -fsSk -G \
  -H "Authorization: Token ${IAST_TOKEN}" \
  --data-urlencode "url=${SERVER}" \
  --data-urlencode "language=java" \
  --data-urlencode "projectName=${IAST_PROJECT_NAME}" \
  --data-urlencode "projectVersion=${VERSION}" \
  --data-urlencode "template_id=${IAST_TEMPLATE_ID}" \
  "${SERVER}/api/v1/agent/download" \
  -o "${AGENT_JAR}"
test -s "${AGENT_JAR}"
unzip -p "${AGENT_JAR}" iast.properties | grep -E '^(iast\.server\.|engine\.|project\.)' || true

echo "==> Install BenchmarkUtils crawler plugin (if missing)"
if ! mvn -Dplugin=org.owasp:benchmarkutils-maven-plugin help:describe >/dev/null 2>&1; then
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkUtils.git /tmp/BenchmarkUtils
  mvn -f /tmp/BenchmarkUtils/pom.xml install -DskipTests -q
fi

echo "==> Start Benchmark with agent"
cd "${ROOT}"
mvn initialize -q
nohup mvn clean package cargo:run -Pdeploywimmunity \
  -D-Dorg.owasp.esapi.logSpecial.discard=true \
  > "${SERVER_LOG}" 2>&1 &
echo $! > "${SERVER_PID}"

echo "==> Wait for Benchmark"
for attempt in $(seq 1 90); do
  if curl -kfsS "${BENCHMARK_BASE_URL}/" >/dev/null 2>&1; then
    echo "Benchmark up after ${attempt} attempt(s)"
    break
  fi
  echo "  waiting... (${attempt}/90)"
  sleep 20
done
curl -kfsS "${BENCHMARK_BASE_URL}/" >/dev/null

echo "==> Verify javaagent on Tomcat JVM"
flags="$(jps -v | grep -F 'iast-tool/agent.jar' | grep -F 'Bootstrap' || true)"
echo "${flags}"
test -n "${flags}"
if echo "${flags}" | grep -Fq 'org.codehaus.plexus.classworlds.launcher.Launcher'; then
  echo "ERROR: agent on Maven Launcher — registration will fail" >&2
  exit 1
fi

echo "==> Agent on Tomcat JVM; wait 30s for panel registration"
sleep 30

echo "==> Crawl"
./runCrawler.sh

echo "==> Wait for traces"
sleep 30

echo "==> Score IAST vs OWASP Benchmark"
export PANEL_URL="${PANEL_URL:-${IAST_SERVER_URL}}"
export PROJECT_VERSION="${VERSION}"
python3 -m pip install -q -r "${ROOT}/security/requirements.txt"
python3 "${ROOT}/security/score_iast_benchmark.py" \
  --output-json "${ROOT}/scorecard-iast.json" \
  --output-md "${ROOT}/scorecard-iast.md"

echo "Done. Scorecard: ${ROOT}/scorecard-iast.md"

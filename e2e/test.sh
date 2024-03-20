#!/bin/bash

set -x

echo "Starting the HTTP server to be monitored"
/src/e2e/fixture/fixture &
FIXTURE_PID=$!

echo "Run gmon"
FILE=/tmp/gmon.log
/src/bin/gmon -path /src/e2e/fixture/fixture -level DEBUG > $FILE 2>&1 &
GMON_PID=$!
sleep 1

echo "curl the HTTP server to create some goroutines of fixture process"
curl -s http://localhost:8080/get/200 > /dev/null
curl -s http://localhost:8080/get/200 > /dev/null
curl -s http://localhost:8080/get/200 > /dev/null
sleep 1

echo "Check if the gmon records the expected number of goroutine events"
if [ $(grep 'goroutine is created' $FILE | wc -l || echo 0) -lt 6 ]; then
    echo "Fail: The count is less than 6."
    echo "--- BEGIN $FILE ---"
    cat $FILE
    echo "--- END $FILE ---"
    exit 1
fi

FILE=/tmp/gmon-metrics.log
echo "write output of GET /metrics to $FILE"
curl -s -o $FILE http://localhost:5500/metrics
patterns=(
    "^gmon_goroutine_creation"
    "^gmon_goroutine_exit"
    "^gmon_goroutine_uptime_bucket"
)
gmon_metric_count=0
for pattern in "${patterns[@]}"; do
    if grep -q "$pattern" "$FILE"; then
        ((gmon_metric_count++))
    fi
done
if [ $gmon_metric_count -lt 3 ]; then
    echo "Fail: /metrics didn't return all the expected metrics"
    echo "--- BEGIN $FILE ---"
    cat $FILE
    echo "--- END $FILE ---"
    exit 1
fi

echo "Success"
kill -9 $FIXTURE_PID
kill -9 $GMON_PID

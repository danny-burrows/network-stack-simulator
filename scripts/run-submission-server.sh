mkdir -p submission/client/logs
for i in $(seq 1 1 4); do python "submission/server/q${i}.py" 'server' > "submission/server/logs/q${i}.txt"; done

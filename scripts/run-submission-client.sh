mkdir -p submission/client/logs
for i in $(seq 1 1 4); do python "submission/client/q${i}.py" 'client' > "submission/client/logs/q${i}.txt"; done

while true; do
	cat /home/coderlava/SnakeGame.java | while IFS= read -r line; do
    	for ((i=0; i<${#line}; i++)); do
        	printf '%s' "${line:i:1}"
        	sleep 0.02
    	done
    	printf '\n'
	done;
done;

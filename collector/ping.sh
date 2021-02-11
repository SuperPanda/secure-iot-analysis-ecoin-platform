# this could be used to build models of the environment
# e.g. used to determine the level of contention with your enviornment
# or whether you are at home or not and could change things accordingly :O the possibilities

# grepping ping
# http://stackoverflow.com/questions/8314219/how-to-get-the-percent-of-packets-received-from-ping-in-bash
while true
do
	ping -c 5 -q google.com | grep -oP 'time \d+' | ./collector-input socket-collector-ping
	sleep 2
done

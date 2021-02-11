# Collector (IoT telemetry source)
* The collector works by using looping bash scripts to act as a "collection source" that pipes output to: input-collector SOURCE
* The collector can specify the source by using the -c argument and the service request by using the -s command
* The collector can request 5 ecoins on startup by using -n5 argument, or whatever number is needed
* To load coins from non-volatile memory, use -l

Unimplemented: the sink :( this could be used to daisy chain collectors

To see a list of all the possible commands: ./collector -h 

## Example usage
The following will create a socket named socket-collector-ping (the -cping argument) which will listen for incoming data streams to the socket and request a service provider named 'average' to compute the collected results every 20 seconds with payment
```
./collector -n100 -cping -saverage -t20
```
Any telemetry data can be streamed to a running collector by piping data into './collector-input socket-collector-<COLLECTOR_NAME>'. The following will pipe the ping response time to google into the collector:
```
ping -c 5 -q google.com | grep -oP 'time \d+' | ./collector-input socket-collector-ping
```


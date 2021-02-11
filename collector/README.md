# Collector (IoT telemetry source)
* The collector works by using looping bash scripts to act as a "collection source" that pipes output to: input-collector SOURCE
* The collector can specify the source by using the -c argument and the service request by using the -s command
* The collector can request 5 ecoins on startup by using -n5 argument, or whatever number is needed
* To load coins from non-volatile memory, use -l

Unimplemented: the sink :( this could be used to daisy chain collectors

To see a list of all the possible commands: ./collector -h 

# Analysts
## Service provider (analyst) interface
An analyst program must implement the interface IAnalyser which has two methods
* byte[] analyse(byte[] in);
* String getServiceName();

The main method should be similar to the following:
```
IAnalyser analyser = new CustomAnalyser();
Analyst.initArgs(args);
Analyst analyst = new Analyst(analyser);
analyst.startService();
```

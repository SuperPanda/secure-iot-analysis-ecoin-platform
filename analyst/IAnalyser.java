/**
 * @author Andrew Briscoe (21332512)
 * @date 2015-05-20
 * @description The required methods to be an analyser
 */

public interface IAnalyser{
    public byte[] analyse(byte[] dataIn);
    public String getServiceName();
}
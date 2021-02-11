/**
 * An almost useless class the demonstrates how the analyst can be used\
 * @author Andrew Briscoe (21332512)
 * @date 2015-05-20
 */
public class SizeAnalyser implements IAnalyser {
        private String serviceName = "byte-counter";

        SizeAnalyser(){

        }
        SizeAnalyser(String name){
            this.serviceName = name;
        }
        public String getServiceName(){
            return this.serviceName;
        }
        public byte[] analyse(byte[] dataIn){
            byte[] result = null;
            try {
                result = ("Result: " + dataIn.length).getBytes("UTF-8");
            } catch (Exception e){
                e.printStackTrace();
            }
            byte[] out = new byte[16];
            System.arraycopy(result,0,out,0,result.length);
            return out;
        }
        public static void main(String[] args){
            IAnalyser analyser = null;
            if (args.length < 5) {
                analyser = new SizeAnalyser();
            } else {
                analyser = new SizeAnalyser(args[4]);
            }
            Analyst.initArgs(args);
            Analyst analyst = new Analyst(analyser);
            analyst.startService();
        }
}
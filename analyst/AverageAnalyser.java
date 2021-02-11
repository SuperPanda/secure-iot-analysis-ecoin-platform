/**
 * Average Analyser
 * @author Andrew Briscoe (21332512)
 * @date 2015-05-20
 * @description An example of how the Analyst can be used
 */
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.lang.Exception;

/**
 * Averages the integer of lines that contain the string 'time'
 * Refer to the collector's ping.sh source for example
 */
public class AverageAnalyser implements IAnalyser {
        private String serviceName = "average";

        public String getServiceName(){
            return this.serviceName;
        }

        AverageAnalyser(){

        }

        AverageAnalyser(String name){
            this.serviceName = name;
        }

        public byte[] analyse(byte[] dataIn){
            InputStream is = new ByteArrayInputStream(dataIn);
            String line = null;
            int i = 0;
            int j = 0;
            try {
                BufferedReader br = new BufferedReader(new InputStreamReader(is,"UTF-8"));
                while ((line = br.readLine()) != null) {
                    if (line.contains("time")){
                        i++;
                        j += Integer.parseInt(line.replaceAll("[\\D]",""));

                    }
                    System.out.println(line);
                }
            } catch (Exception ignored){

            }
            System.out.println("sum: " + j + ", n: " + i);
            byte[] result = null;
            try {
                if (i == 0){
                    result = ("Average: NaN").getBytes("UTF-8");
                } else {
                    result = ("Average: " + ((float) j / (float) i)).getBytes("UTF-8");
                }
            } catch (Exception e){
                e.printStackTrace();
            }
            byte[] out = new byte[32];
            System.arraycopy(result,0,out,0,result.length);
            return out;
        }
        public static void main(String[] args){
            IAnalyser analyser = null;
            if (args.length < 5) {
                analyser = new AverageAnalyser();
            } else {
                analyser = new AverageAnalyser(args[4]);
            }
            Analyst.initArgs(args);
            Analyst analyst = new Analyst(analyser);
            analyst.startService();
        }
}
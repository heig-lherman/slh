
public class Chall {

    final static int MAXIMUM_CENTS_ALLOWED = 100000;

    public static void transfer(int francs) {
        if (francs > 1000){
            System.out.println("Congrats! You solved the challenge!");
        }
        else{
            System.out.println(francs + " francs were transmitted on the account.");
        }
    }

    public static void sendMoney(int francs) {
        if (francs*100 <= MAXIMUM_CENTS_ALLOWED) {
            transfer(francs);
        }
        else{
            System.out.println("You are not allowed to transfer more than "+ MAXIMUM_CENTS_ALLOWED +  " centimes. The transfer was cancelled");
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("One argument needed: amount in francs to transfer.");
            System.out.println("WARNING: you are not allowed to transfer more than " + MAXIMUM_CENTS_ALLOWED + " centimes.");
        }
        else {
            int francs = Integer.valueOf(args[0]);
            sendMoney(francs);
        }
    }
}

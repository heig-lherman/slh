import java.util.InputMismatchException;
import java.util.Scanner;

public class Chall2 {
    static boolean admin = false;
    final static int MAX_AMOUNT = 1000;
    static Scanner in = new Scanner(System.in);
    public static void becomeAdmin() {
        admin = true;
    }
    public static void removeAdmin() {
        admin = false;
    }

    public static void sendMoney(int amount) {
        if (!admin){
            System.out.println("You have to be admin to send money.");
        }
        else{
            if(amount > MAX_AMOUNT){
                System.out.println("Congrats! You solved the challenge.");
                System.exit(0);
            }
            else {
                System.out.println("Money sent:(" +amount +"CHF)");
            }
        }
    }

    public static void sendSmallAmount(){
        try {
            System.out.println("You are sending a small amount (max " + MAX_AMOUNT + "). Please enter the amount.");
            becomeAdmin();
            int amount = in.nextInt();
            if (amount > MAX_AMOUNT) {
                System.out.println("You are not allowed to send this amount.");
            } else {
                sendMoney(amount);
            }
            removeAdmin();
        }
        catch (InputMismatchException e){
            in.nextLine();//Clean mess
            System.out.println("You have to enter an integer. ");
        }
    }
    public static void sendBigAmount() {
        if (admin) {
            try {
                System.out.println("You are admin. How much do you want to send?");
                int amount = in.nextInt();
                sendMoney(amount);
            }
            catch (InputMismatchException e){
                in.nextLine();//Clean mess
                System.out.println("You have to enter an integer. ");
            }
        }
        else {
            System.out.println("You are not admin.");
        }
    }


    public static void printMenu(){
        System.out.println("Select option:");
        System.out.println("1: send small amount");
        System.out.println("2: send arbitrary amount (admin required)");
    }

    public static int askChoice(int maxNumber){
        int choice = 0;
        while (choice < 1 || choice > maxNumber) {
            System.out.println("Enter a number between 1 and " +maxNumber);
            try {
                choice = in.nextInt();
            }
            catch (InputMismatchException e){
                in.nextLine();//Clean mess
                System.out.println("You have to enter an integer. Try again. ");
            }
        }
        return choice;
    }

    public static void main(String[] args) {
        while(true){
            printMenu();
            int choice = askChoice(2);
            switch (choice){
                case 1: sendSmallAmount();
                break;
                case 2: sendBigAmount();
                break;
                default:
                    throw new IllegalArgumentException("Wrong choice in switch. ");
            }
        }

    }
}

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package argon2hashpassword;

/**
 *
 * @author basile
 */
public class Main {
    public static void main(String[] args) {
        String hash = Argon2.getInstance().generateHashArgon2Password("password");
        System.out.println(hash);
    }
}

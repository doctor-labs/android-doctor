package demo;
import java.util.*;
public class Main implements Runnable {
    static final String KEY = "s3cr3t-\u0000-😀";
    private int count;
    public long big = 0x123456789abcdefL;
    public static int sw(int x) {
        switch (x) { case 1: return 10; case 2: return 20; case 3: return 30; case 100: return 5; default: return -1; }
    }
    public static int sw2(int x) {
        switch (x) { case 1: return 10; case 1000: return 20; case 100000: return 30; default: return -1; }
    }
    public void run() {
        count++;
        byte[] a = {1,2,3,4,5};
        List<String> l = new ArrayList<>();
        l.add(KEY);
        try { Object o = Class.forName("demo.Main"); System.out.println(o + " " + a.length + big + 1.5f + 2.5); }
        catch (Exception e) { throw new RuntimeException(e); }
        synchronized (this) { count += 2; }
    }
    public static void main(String[] args) { new Main().run(); int[][] g = new int[3][4]; long z = sw(2) * 3L / 7; Runnable r = () -> System.out.println("lam"); r.run(); }
}
